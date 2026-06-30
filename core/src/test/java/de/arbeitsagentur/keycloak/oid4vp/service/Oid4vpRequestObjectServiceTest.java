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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

class Oid4vpRequestObjectServiceTest {

    private Oid4vpRequestObjectService service;
    private KeycloakSession session;
    private Oid4vpRequestObjectStore store;
    private Oid4vpRedirectFlowService redirectFlowService;
    private AuthenticationSessionModel authSession;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");

        Oid4vpIdentityProvider provider = mock(Oid4vpIdentityProvider.class);
        Oid4vpIdentityProviderConfig config = mock(Oid4vpIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.isEnforceHaip()).thenReturn(true);
        when(config.getClientIdScheme()).thenReturn("x509_hash");
        when(config.getResolvedResponseMode()).thenReturn(Oid4vpResponseMode.DIRECT_POST_JWT);
        when(config.isUseIdTokenSubject()).thenReturn(false);
        when(provider.getConfig()).thenReturn(config);
        when(provider.prepareDcqlQueryFromConfig())
                .thenReturn(new PreparedDcqlQuery("{\"credentials\":[]}", List.of()));
        redirectFlowService = mock(Oid4vpRedirectFlowService.class);
        when(provider.getRedirectFlowService()).thenReturn(redirectFlowService);

        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);

        store = mock(Oid4vpRequestObjectStore.class);
        authSession = mock(AuthenticationSessionModel.class);
        Oid4vpAuthSessionResolver authSessionResolver = mock(Oid4vpAuthSessionResolver.class);
        when(authSessionResolver.resolveFromTokenEntry("root-session", "tab-1")).thenReturn(authSession);

        Oid4vpEndpointResponseFactory responseFactory = new Oid4vpEndpointResponseFactory(session, realm, config);
        service = new Oid4vpRequestObjectService(session, provider, store, authSessionResolver, responseFactory);
    }

    @Test
    void generateRequestObject_signsUsingStoredRequestContext() throws Exception {
        when(store.resolveByState(session, "tab-1.abc")).thenReturn(requestContext("tab-1.abc", "nonce-1"));
        when(redirectFlowService.buildSignedRequestObject(any(RequestObjectParams.class)))
                .thenReturn(new SignedRequestObject("signed-jwt", "{\"kid\":\"kid-1\"}"));

        Response response = service.generateRequestObject("tab-1.abc", null, null);

        assertThat(response.getStatus()).isEqualTo(200);
        ArgumentCaptor<RequestObjectParams> captor = ArgumentCaptor.forClass(RequestObjectParams.class);
        verify(redirectFlowService).buildSignedRequestObject(captor.capture());
        RequestObjectParams params = captor.getValue();
        assertThat(params.state()).isEqualTo("tab-1.abc");
        assertThat(params.nonce()).isEqualTo("nonce-1");
        assertThat(params.responseUri()).isEqualTo("https://example.com/endpoint");
        assertThat(params.responseEncryptionKeyJson()).isEqualTo("{\"kid\":\"enc-key\"}");
        // The request context is allocated at render time, not on fetch.
        verify(store, never()).storeRequestContext(any(), any());
        verify(redirectFlowService, never()).createResponseEncryptionKey();
    }

    @Test
    void generateRequestObject_repeatedFetchesReuseSameStateAndNonce() throws Exception {
        when(store.resolveByState(session, "tab-1.abc")).thenReturn(requestContext("tab-1.abc", "nonce-1"));
        when(redirectFlowService.buildSignedRequestObject(any(RequestObjectParams.class)))
                .thenReturn(new SignedRequestObject("signed-jwt", "{\"kid\":\"kid-1\"}"));

        service.generateRequestObject("tab-1.abc", null, null);
        service.generateRequestObject("tab-1.abc", null, null);

        ArgumentCaptor<RequestObjectParams> captor = ArgumentCaptor.forClass(RequestObjectParams.class);
        verify(redirectFlowService, times(2)).buildSignedRequestObject(captor.capture());
        List<RequestObjectParams> values = captor.getAllValues();
        assertThat(values.get(0).state()).isEqualTo(values.get(1).state());
        assertThat(values.get(0).nonce()).isEqualTo(values.get(1).nonce());
    }

    @Test
    void generateRequestObject_unknownState_returnsNotFound() {
        when(store.resolveByState(session, "missing")).thenReturn(null);

        Response response = service.generateRequestObject("missing", null, null);

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void generateRequestObject_expiredAuthSession_returnsBadRequest() {
        Oid4vpRequestObjectStore.RequestContextEntry entry = new Oid4vpRequestObjectStore.RequestContextEntry(
                "tab-1.abc",
                "missing-root",
                "tab-1",
                "effective-client",
                "https://example.com/endpoint",
                "same_device",
                "nonce-1",
                "{\"kid\":\"enc-key\"}",
                "thumbprint",
                List.of());
        when(store.resolveByState(session, "tab-1.abc")).thenReturn(entry);

        Response response = service.generateRequestObject("tab-1.abc", null, null);

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void generateRequestObject_buildFailure_returnsServerErrorAndDoesNotRemoveContext() throws Exception {
        when(store.resolveByState(session, "tab-1.abc")).thenReturn(requestContext("tab-1.abc", "nonce-1"));
        when(redirectFlowService.buildSignedRequestObject(any(RequestObjectParams.class)))
                .thenThrow(new IllegalStateException("boom"));

        Response response = service.generateRequestObject("tab-1.abc", null, null);

        assertThat(response.getStatus()).isEqualTo(500);
        verify(store, never()).removeRequestContext(eq(session), anyString());
    }

    private static Oid4vpRequestObjectStore.RequestContextEntry requestContext(String state, String nonce) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                "root-session",
                "tab-1",
                "effective-client",
                "https://example.com/endpoint",
                "same_device",
                nonce,
                "{\"kid\":\"enc-key\"}",
                "thumbprint",
                List.of());
    }
}
