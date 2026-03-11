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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

class Oid4vpIdentityProviderEndpointTest {

    private Oid4vpIdentityProviderEndpoint endpoint;
    private KeycloakSession session;
    private Oid4vpIdentityProvider provider;
    private Oid4vpIdentityProviderConfig config;
    private Oid4vpRequestObjectStore store;
    private AuthenticationSessionModel authSession;
    private KeycloakContext context;

    @BeforeEach
    void setUp() {
        CryptoIntegration.init(Oid4vpIdentityProviderEndpointTest.class.getClassLoader());

        session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");

        provider = mock(Oid4vpIdentityProvider.class);
        config = mock(Oid4vpIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.getSsePollIntervalMs()).thenReturn(2000);
        when(config.getSseTimeoutSeconds()).thenReturn(120);
        when(config.getSsePingIntervalSeconds()).thenReturn(10);
        when(config.getCrossDeviceCompleteTtlSeconds()).thenReturn(300);
        when(config.isEnforceHaip()).thenReturn(true);
        when(config.getResolvedResponseMode()).thenReturn(Oid4vpResponseMode.DIRECT_POST_JWT);
        when(provider.getConfig()).thenReturn(config);
        when(config.getClientIdScheme()).thenReturn("x509_hash");
        when(config.isUseIdTokenSubject()).thenReturn(false);

        context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(uriInfo.getRequestUri())
                .thenReturn(URI.create("http://localhost:8080/realms/test/broker/oid4vp/endpoint"));
        when(context.getUri()).thenReturn(uriInfo);
        when(session.getContext()).thenReturn(context);
        when(session.singleUseObjects()).thenReturn(mock(SingleUseObjectProvider.class));

        AbstractIdentityProvider.AuthenticationCallback callback =
                mock(AbstractIdentityProvider.AuthenticationCallback.class);
        EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);

        store = mock(Oid4vpRequestObjectStore.class);

        AuthenticationSessionProvider authSessions = mock(AuthenticationSessionProvider.class);
        RootAuthenticationSessionModel rootAuthSession = mock(RootAuthenticationSessionModel.class);
        authSession = mock(AuthenticationSessionModel.class);
        when(session.authenticationSessions()).thenReturn(authSessions);
        when(authSessions.getRootAuthenticationSession(realm, "root-session")).thenReturn(rootAuthSession);
        when(rootAuthSession.getAuthenticationSessions()).thenReturn(Map.of("tab-1", authSession));
        ClientModel client = mock(ClientModel.class);
        when(authSession.getClient()).thenReturn(client);
        when(client.getId()).thenReturn("client-1");
        when(authSession.getTabId()).thenReturn("tab-1");
        when(authSession.getParentSession()).thenReturn(rootAuthSession);
        when(rootAuthSession.getId()).thenReturn("root-session");

        endpoint = new Oid4vpIdentityProviderEndpoint(session, realm, provider, callback, event, store);
    }

    @Test
    void handlePost_withNoSessionMatch_returnsSessionExpiredError() {
        Response response = endpoint.handlePost(null, null, null, null, null, null, null);
        assertThat(response.getStatus()).isEqualTo(400);
        String body = (String) response.getEntity();
        assertThat(body).contains("session_expired");
    }

    @Test
    void handlePost_withEncryptedResponseAndPostedState_decryptsErrorPayload() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-1").generate();
        String encryptedResponse =
                encryptPayload(key, Map.of("error", "access_denied", "error_description", "Wallet rejected"));

        when(store.resolveByKid(session, "kid-1"))
                .thenReturn(requestContext("handle-1", "state-1", "nonce-1", key.toJSONString()));

        Response response = endpoint.handlePost(null, "state-1", null, null, encryptedResponse, null, null);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat((String) response.getEntity())
                .contains("redirect_uri")
                .contains("access_denied")
                .contains("Wallet+rejected");
    }

    @Test
    void handlePost_withEncryptedResponseAndMismatchedPostedState_returnsError() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-2").generate();
        String encryptedResponse = encryptPayload(key, Map.of("error", "access_denied"));

        when(store.resolveByKid(session, "kid-2"))
                .thenReturn(requestContext("handle-1", "state-expected", "nonce-2", key.toJSONString()));

        Response response = endpoint.handlePost(null, "state-actual", null, null, encryptedResponse, null, null);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat((String) response.getEntity()).contains("redirect_uri").contains("state+does+not+match");
    }

    @Test
    void handlePost_withEncryptedResponseAndMissingPostedState_recoversStateFromKidContext() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-retry").generate();
        String encryptedResponse =
                encryptPayload(key, Map.of("error", "access_denied", "error_description", "Wallet rejected"));

        when(store.resolveByKid(session, "kid-retry"))
                .thenReturn(requestContext("handle-1", "state-1", "nonce-1", key.toJSONString()));

        Response response = endpoint.handlePost(null, null, null, null, encryptedResponse, null, null);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat((String) response.getEntity()).contains("redirect_uri").contains("access_denied");
        verify(store).resolveByKid(session, "kid-retry");
    }

    @Test
    void crossDeviceStatus_withMismatchedBrowserSession_throwsForbidden() {
        when(store.resolveFlowHandle(session, "handle-1"))
                .thenReturn(new Oid4vpRequestObjectStore.FlowContextEntry(
                        "root-session", "tab-1", "effective-client", "https://example.com/endpoint"));
        when(context.getAuthenticationSession()).thenReturn(null);

        assertThatThrownBy(() -> endpoint.crossDeviceStatus("handle-1", null, null))
                .isInstanceOf(ForbiddenException.class)
                .hasMessageContaining("Current browser session does not match");
    }

    private String encryptPayload(ECKey key, Map<String, Object> payload) throws Exception {
        String payloadJson = JsonSerialization.writeValueAsString(payload);
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID(key.getKeyID())
                        .build(),
                new Payload(payloadJson));
        jwe.encrypt(new ECDHEncrypter(key.toPublicJWK()));
        return jwe.serialize();
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String requestHandle, String state, String nonce, String encryptionKeyJson) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                requestHandle,
                "root-session",
                "tab-1",
                state,
                "effective-client",
                "https://example.com/endpoint",
                nonce,
                encryptionKeyJson,
                "thumbprint");
    }
}
