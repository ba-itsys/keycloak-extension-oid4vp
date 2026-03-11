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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
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
        when(provider.buildDcqlQueryFromConfig()).thenReturn("{\"credentials\":[]}");
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
    void generateRequestObject_issuesFreshRequestContextForRepeatedFetches() throws Exception {
        Oid4vpRequestObjectStore.FlowContextEntry flowContext = new Oid4vpRequestObjectStore.FlowContextEntry(
                "root-session", "tab-1", "effective-client", "https://example.com/endpoint");
        when(store.resolveFlowHandle(session, "handle-1")).thenReturn(flowContext);
        when(redirectFlowService.createResponseEncryptionKey())
                .thenReturn(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"))
                .thenReturn(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"));
        when(redirectFlowService.buildSignedRequestObject(any(RequestObjectParams.class)))
                .thenReturn(new SignedRequestObject("signed-jwt-1", "{\"kid\":\"kid-1\"}"))
                .thenReturn(new SignedRequestObject("signed-jwt-2", "{\"kid\":\"kid-2\"}"));

        Response first = service.generateRequestObject("handle-1", null, null);
        Response second = service.generateRequestObject("handle-1", null, null);

        assertThat(first.getStatus()).isEqualTo(200);
        assertThat(second.getStatus()).isEqualTo(200);

        ArgumentCaptor<RequestObjectParams> captor = ArgumentCaptor.forClass(RequestObjectParams.class);
        verify(redirectFlowService, times(2)).buildSignedRequestObject(captor.capture());
        ArgumentCaptor<Oid4vpRequestObjectStore.RequestContextEntry> requestContextCaptor =
                ArgumentCaptor.forClass(Oid4vpRequestObjectStore.RequestContextEntry.class);
        verify(store, times(2)).storeRequestContext(eq(session), requestContextCaptor.capture());

        List<RequestObjectParams> values = captor.getAllValues();
        assertThat(values).hasSize(2);
        assertThat(values.get(0).state()).isNotEqualTo(values.get(1).state());
        assertThat(values.get(0).nonce()).isNotEqualTo(values.get(1).nonce());
        assertThat(values.get(0).responseUri()).isEqualTo("https://example.com/endpoint");
        assertThat(values.get(1).responseUri()).isEqualTo("https://example.com/endpoint");
        assertThat(values.get(0).responseEncryptionKeyJson())
                .isNotEqualTo(values.get(1).responseEncryptionKeyJson());
        assertThat(requestContextCaptor.getAllValues()).hasSize(2);
        assertThat(requestContextCaptor.getAllValues().get(0).requestHandle()).isEqualTo("handle-1");
        assertThat(requestContextCaptor.getAllValues().get(1).requestHandle()).isEqualTo("handle-1");
        verify(authSession, never()).setAuthNote(any(), any());
    }
}
