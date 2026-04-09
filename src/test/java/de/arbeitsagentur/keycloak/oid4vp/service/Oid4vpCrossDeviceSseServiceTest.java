/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService.CROSS_DEVICE_COMPLETE_PREFIX;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.sse.OutboundSseEvent;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

class Oid4vpCrossDeviceSseServiceTest {

    private KeycloakSession session;
    private KeycloakSessionFactory sessionFactory;
    private SingleUseObjectProvider singleUseObjects;
    private RealmProvider realmProvider;
    private AuthenticationSessionProvider authenticationSessions;
    private Oid4vpIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        Oid4vpCrossDeviceSseService.resetCoordinatorsForTests();

        session = mock(KeycloakSession.class);
        sessionFactory = mock(KeycloakSessionFactory.class);
        RealmModel realm = mock(RealmModel.class);

        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(realm.getName()).thenReturn("test-realm");

        config = new Oid4vpIdentityProviderConfig();
        config.setSsePollIntervalMs(25);
        config.setSseTimeoutSeconds(1);
        config.setSsePingIntervalSeconds(1);

        singleUseObjects = mock(SingleUseObjectProvider.class);
        realmProvider = mock(RealmProvider.class);
        authenticationSessions = mock(AuthenticationSessionProvider.class);
    }

    @AfterEach
    void tearDown() {
        Oid4vpCrossDeviceSseService.resetCoordinatorsForTests();
    }

    @Test
    void subscribe_sendsCompleteWhenSharedSignalExists() throws Exception {
        Oid4vpCrossDeviceSseService service = createService();
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();

        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "test-handle"))
                .thenReturn(
                        Map.of("complete_auth_url", "http://localhost:8080/complete-auth?request_handle=test-handle"));

        service.subscribe("test-handle", sink, sse.sse());

        verify(sse.builder(), timeout(1000)).name("complete");
        verify(sse.builder(), timeout(1000))
                .data(
                        String.class,
                        "{\"redirect_uri\":\"http://localhost:8080/complete-auth?request_handle=test-handle\"}");
        verify(sink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(sink, timeout(1000)).close();
    }

    @Test
    void subscribe_keepsConnectionOpenAndSendsPingBeforeTimeout() throws Exception {
        config.setSseTimeoutSeconds(5);
        Oid4vpCrossDeviceSseService service = createService();
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();

        when(singleUseObjects.get(anyString())).thenReturn(null);

        service.subscribe("test-handle", sink, sse.sse());

        verify(sse.builder(), timeout(2000)).name("ping");
        verify(sse.builder(), timeout(2000)).data(String.class, "{}");
        verify(sink, timeout(2000)).send(any(OutboundSseEvent.class));
        verify(sink, after(1500).never()).close();
        closed.set(true);
    }

    @Test
    void subscribe_sendsTimeoutAndClosesExpiredConnection() throws Exception {
        config.setSseTimeoutSeconds(0);
        Oid4vpCrossDeviceSseService service = createService();
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();

        when(singleUseObjects.get(anyString())).thenReturn(null);

        service.subscribe("test-handle", sink, sse.sse());

        verify(sse.builder(), timeout(1000)).name("timeout");
        verify(sse.builder(), timeout(1000)).data(String.class, "{\"error\":\"timeout\"}");
        verify(sink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(sink, timeout(1000)).close();
    }

    @Test
    void subscribe_sendsErrorAndClosesWhenRealmIsMissing() throws Exception {
        KeycloakSession pollingSession = mock(KeycloakSession.class);
        KeycloakTransactionManager tx = mock(KeycloakTransactionManager.class);
        when(sessionFactory.create()).thenReturn(pollingSession);
        when(pollingSession.getTransactionManager()).thenReturn(tx);
        when(pollingSession.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealmByName("test-realm")).thenReturn(null);

        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        Oid4vpCrossDeviceSseService service = new Oid4vpCrossDeviceSseService(session, realm, config);
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();

        service.subscribe("test-handle", sink, sse.sse());

        verify(sse.builder(), timeout(1000)).name("error");
        verify(sse.builder(), timeout(1000)).data(String.class, "{\"error\":\"realm_not_found\"}");
        verify(sink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(sink, timeout(1000)).close();
    }

    @Test
    void subscribe_supportsMultipleLocalListenersForSameHandle() throws Exception {
        Oid4vpCrossDeviceSseService service = createService();
        AtomicBoolean firstClosed = new AtomicBoolean(false);
        AtomicBoolean secondClosed = new AtomicBoolean(false);
        SseEventSink firstSink = mockTrackedSink(firstClosed);
        SseEventSink secondSink = mockTrackedSink(secondClosed);
        MockSseContext sse = mockSse();

        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "test-handle"))
                .thenReturn(
                        Map.of("complete_auth_url", "http://localhost:8080/complete-auth?request_handle=test-handle"));

        service.subscribe("test-handle", firstSink, sse.sse());
        service.subscribe("test-handle", secondSink, sse.sse());

        verify(firstSink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(firstSink, timeout(1000)).close();
        verify(secondSink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(secondSink, timeout(1000)).close();
    }

    @Test
    void subscribe_sendsExpiredWhenAuthenticationSessionDisappears() throws Exception {
        Oid4vpCrossDeviceSseService service = createService();
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);

        when(authSession.getParentSession()).thenReturn(rootSession);
        when(rootSession.getId()).thenReturn("root-session");
        when(authSession.getTabId()).thenReturn("tab-1");
        when(authenticationSessions.getRootAuthenticationSession(any(), eq("root-session")))
                .thenReturn(null);
        when(singleUseObjects.get(anyString())).thenReturn(null);

        service.subscribe("test-handle", sink, sse.sse(), authSession);

        verify(sse.builder(), timeout(1000)).name("expired");
        verify(sse.builder(), timeout(1000)).data(String.class, "{\"error\":\"authentication_session_expired\"}");
        verify(sink, timeout(1000)).send(any(OutboundSseEvent.class));
        verify(sink, timeout(1000)).close();
    }

    @Test
    void subscribe_sendsErrorImmediatelyWhenSessionFactoryIsMissing() {
        KeycloakSession sessionWithoutFactory = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");

        Oid4vpCrossDeviceSseService service = new Oid4vpCrossDeviceSseService(sessionWithoutFactory, realm, config);
        AtomicBoolean closed = new AtomicBoolean(false);
        SseEventSink sink = mockTrackedSink(closed);
        MockSseContext sse = mockSse();

        service.subscribe("test-handle", sink, sse.sse());

        verify(sse.builder()).name("error");
        verify(sse.builder()).data(String.class, "{\"error\":\"sse_unavailable\"}");
        verify(sink).send(any(OutboundSseEvent.class));
        verify(sink).close();
    }

    private Oid4vpCrossDeviceSseService createService() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");

        KeycloakSession pollingSession = mock(KeycloakSession.class);
        KeycloakTransactionManager tx = mock(KeycloakTransactionManager.class);
        RealmModel pollingRealm = mock(RealmModel.class);

        when(sessionFactory.create()).thenReturn(pollingSession);
        when(pollingSession.getTransactionManager()).thenReturn(tx);
        when(pollingSession.realms()).thenReturn(realmProvider);
        when(pollingSession.authenticationSessions()).thenReturn(authenticationSessions);
        when(realmProvider.getRealmByName("test-realm")).thenReturn(pollingRealm);
        when(pollingSession.singleUseObjects()).thenReturn(singleUseObjects);

        return new Oid4vpCrossDeviceSseService(session, realm, config);
    }

    private SseEventSink mockTrackedSink(AtomicBoolean closed) {
        SseEventSink sink = mock(SseEventSink.class);
        when(sink.isClosed()).thenAnswer(invocation -> closed.get());
        doAnswer(invocation -> {
                    closed.set(true);
                    return null;
                })
                .when(sink)
                .close();
        return sink;
    }

    private MockSseContext mockSse() {
        Sse sse = mock(Sse.class);
        OutboundSseEvent.Builder builder = mock(OutboundSseEvent.Builder.class);
        OutboundSseEvent event = mock(OutboundSseEvent.class);

        when(sse.newEventBuilder()).thenReturn(builder);
        when(builder.name(anyString())).thenReturn(builder);
        when(builder.mediaType(MediaType.APPLICATION_JSON_TYPE)).thenReturn(builder);
        when(builder.data(eq(String.class), any())).thenReturn(builder);
        when(builder.build()).thenReturn(event);
        return new MockSseContext(sse, builder);
    }

    private record MockSseContext(Sse sse, OutboundSseEvent.Builder builder) {}
}
