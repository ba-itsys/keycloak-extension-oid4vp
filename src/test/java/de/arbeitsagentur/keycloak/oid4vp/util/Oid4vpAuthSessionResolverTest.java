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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

class Oid4vpAuthSessionResolverTest {

    private KeycloakSession session;
    private RealmModel realm;
    private Oid4vpRequestObjectStore requestObjectStore;
    private Oid4vpAuthSessionResolver resolver;
    private AuthenticationSessionModel authSession;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        requestObjectStore = mock(Oid4vpRequestObjectStore.class);
        resolver = new Oid4vpAuthSessionResolver(session, realm, requestObjectStore);

        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        authSession = mock(AuthenticationSessionModel.class);
        ClientModel client = mock(ClientModel.class);
        AuthenticationSessionProvider provider = mock(AuthenticationSessionProvider.class);
        KeycloakContext context = mock(KeycloakContext.class);

        when(session.authenticationSessions()).thenReturn(provider);
        when(session.getContext()).thenReturn(context);
        when(provider.getRootAuthenticationSession(realm, "root-1")).thenReturn(rootSession);
        when(rootSession.getAuthenticationSessions()).thenReturn(Map.of("tab-1", authSession));
        when(authSession.getParentSession()).thenReturn(rootSession);
        when(authSession.getClient()).thenReturn(client);
        when(authSession.getTabId()).thenReturn("tab-1");
        when(rootSession.getId()).thenReturn("root-1");
        when(client.getId()).thenReturn("client-1");
    }

    @Test
    void resolveFromStore_usesStoredTabIdWhenNoHintIsProvided() {
        when(requestObjectStore.resolveByState(session, "state-1")).thenReturn(requestContext("tab-1"));

        AuthenticationSessionModel resolved = resolver.resolveFromStore("state-1", null);

        assertThat(resolved).isSameAs(authSession);
    }

    @Test
    void resolveFromStore_fallsBackToStatePrefixWhenRequestContextHasNoTabId() {
        when(requestObjectStore.resolveByState(session, "tab-1.random"))
                .thenReturn(new Oid4vpRequestObjectStore.RequestContextEntry(
                        "handle-1",
                        "root-1",
                        null,
                        "tab-1.random",
                        "client",
                        "https://example.com/endpoint",
                        "same_device",
                        "nonce",
                        null,
                        null));

        AuthenticationSessionModel resolved = resolver.resolveFromStore("tab-1.random", null);

        assertThat(resolved).isSameAs(authSession);
    }

    @Test
    void resolveFromRequestContext_returnsNullForMissingContext() {
        assertThat(resolver.resolveFromRequestContext(null)).isNull();
    }

    @Test
    void resolveFromTokenEntry_returnsNullWhenRootSessionIsMissing() {
        assertThat(resolver.resolveFromTokenEntry("missing-root", "tab-1")).isNull();
    }

    @Test
    void resolveCurrentBrowserSession_prefersCurrentContextWhenSessionMatches() {
        AuthenticationSessionModel expected = authSession;
        when(session.getContext().getAuthenticationSession()).thenReturn(expected);

        AuthenticationSessionModel resolved = resolver.resolveCurrentBrowserSession(expected);

        assertThat(resolved).isSameAs(expected);
    }

    @Test
    void sameAuthenticationSession_comparesRootSessionTabAndClient() {
        AuthenticationSessionModel same = mock(AuthenticationSessionModel.class);
        RootAuthenticationSessionModel sameRoot = mock(RootAuthenticationSessionModel.class);
        ClientModel sameClient = mock(ClientModel.class);
        when(same.getParentSession()).thenReturn(sameRoot);
        when(sameRoot.getId()).thenReturn("root-1");
        when(same.getTabId()).thenReturn("tab-1");
        when(same.getClient()).thenReturn(sameClient);
        when(sameClient.getId()).thenReturn("client-1");

        assertThat(resolver.sameAuthenticationSession(authSession, same)).isTrue();
        assertThat(resolver.sameAuthenticationSession(authSession, null)).isFalse();
    }

    private static Oid4vpRequestObjectStore.RequestContextEntry requestContext(String tabId) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-1",
                tabId,
                "state-1",
                "client",
                "https://example.com/endpoint",
                "same_device",
                "nonce",
                null,
                null);
    }
}
