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
package de.arbeitsagentur.keycloak.oid4vp;

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpDirectPostService.CROSS_DEVICE_COMPLETE_PREFIX;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.SingleUseObjectProvider;

class Oid4vpCrossDeviceSseServiceTest {

    private KeycloakSession session;
    private KeycloakSessionFactory sessionFactory;
    private SingleUseObjectProvider singleUseObjects;
    private Oid4vpIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        sessionFactory = mock(KeycloakSessionFactory.class);
        RealmModel realm = mock(RealmModel.class);

        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(realm.getName()).thenReturn("test-realm");

        config = new Oid4vpIdentityProviderConfig();
        // Use short intervals for fast tests
        config.setSsePollIntervalMs(10);
        config.setSseTimeoutSeconds(1);
        config.setSsePingIntervalSeconds(1);

        singleUseObjects = mock(SingleUseObjectProvider.class);
    }

    private Oid4vpCrossDeviceSseService createService() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        return new Oid4vpCrossDeviceSseService(session, realm, config);
    }

    private KeycloakSession mockPollingSession() {
        KeycloakSession pollingSession = mock(KeycloakSession.class);
        KeycloakTransactionManager tx = mock(KeycloakTransactionManager.class);
        RealmProvider realmProvider = mock(RealmProvider.class);
        RealmModel pollingRealm = mock(RealmModel.class);

        when(sessionFactory.create()).thenReturn(pollingSession);
        when(pollingSession.getTransactionManager()).thenReturn(tx);
        when(pollingSession.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealmByName("test-realm")).thenReturn(pollingRealm);
        when(pollingSession.singleUseObjects()).thenReturn(singleUseObjects);

        return pollingSession;
    }

    @Test
    void buildSseResponse_returnsEventStreamContentType() {
        Oid4vpCrossDeviceSseService service = createService();

        Response response = service.buildSseResponse("test-state");

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("text/event-stream");
        assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-cache");
        assertThat(response.getHeaderString("X-Accel-Buffering")).isEqualTo("no");
    }

    @Test
    void buildSseResponse_sendsCompleteOnSignal() throws Exception {
        mockPollingSession();
        String completeUrl = "http://localhost:8080/complete-auth?state=abc";
        when(singleUseObjects.remove(CROSS_DEVICE_COMPLETE_PREFIX + "test-state"))
                .thenReturn(Map.of("complete_auth_url", completeUrl));

        Oid4vpCrossDeviceSseService service = createService();
        Response response = service.buildSseResponse("test-state");

        String output = streamToString(response);
        assertThat(output).contains("event: complete");
        assertThat(output).contains(completeUrl);
        assertThat(output).doesNotContain("event: timeout");
    }

    @Test
    void buildSseResponse_sendsTimeoutWhenNoSignal() throws Exception {
        mockPollingSession();
        when(singleUseObjects.remove(anyString())).thenReturn(null);

        config.setSseTimeoutSeconds(1);
        config.setSsePollIntervalMs(50);

        Oid4vpCrossDeviceSseService service = createService();
        Response response = service.buildSseResponse("test-state");

        String output = streamToString(response);
        assertThat(output).contains("event: timeout");
        assertThat(output).contains("\"error\":\"timeout\"");
    }

    @Test
    void buildSseResponse_sendsPingEvents() throws Exception {
        mockPollingSession();
        when(singleUseObjects.remove(anyString())).thenReturn(null);

        config.setSseTimeoutSeconds(1);
        config.setSsePollIntervalMs(50);
        config.setSsePingIntervalSeconds(1);

        Oid4vpCrossDeviceSseService service = createService();
        Response response = service.buildSseResponse("test-state");

        String output = streamToString(response);
        assertThat(output).contains("event: ping");
    }

    @Test
    void buildSseResponse_sendsErrorWhenRealmNotFound() throws Exception {
        KeycloakSession pollingSession = mock(KeycloakSession.class);
        KeycloakTransactionManager tx = mock(KeycloakTransactionManager.class);
        RealmProvider realmProvider = mock(RealmProvider.class);

        when(sessionFactory.create()).thenReturn(pollingSession);
        when(pollingSession.getTransactionManager()).thenReturn(tx);
        when(pollingSession.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealmByName("test-realm")).thenReturn(null);

        Oid4vpCrossDeviceSseService service = createService();
        Response response = service.buildSseResponse("test-state");

        String output = streamToString(response);
        assertThat(output).contains("event: error");
        assertThat(output).contains("realm_not_found");
    }

    @Test
    void buildSseResponse_configAffectsIterationCount() throws Exception {
        mockPollingSession();
        when(singleUseObjects.remove(anyString())).thenReturn(null);

        // 200ms timeout with 100ms interval = 2 iterations
        config.setSseTimeoutSeconds(1);
        config.setSsePollIntervalMs(500);

        Oid4vpCrossDeviceSseService service = createService();
        Response response = service.buildSseResponse("test-state");

        String output = streamToString(response);
        assertThat(output).contains("event: timeout");
        // Should have polled singleUseObjects only a few times (timeout/interval)
        verify(singleUseObjects, atMost(3)).get(anyString());
    }

    private String streamToString(Response response) throws Exception {
        StreamingOutput stream = (StreamingOutput) response.getEntity();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        stream.write(baos);
        return baos.toString(StandardCharsets.UTF_8);
    }
}
