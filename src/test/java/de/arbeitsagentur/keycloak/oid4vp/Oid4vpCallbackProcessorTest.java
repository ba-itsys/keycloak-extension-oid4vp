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

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.sessions.AuthenticationSessionModel;

class Oid4vpCallbackProcessorTest {

    private Oid4vpCallbackProcessor processor;
    private Oid4vpIdentityProviderConfig config;
    private Oid4vpIdentityProvider provider;
    private AuthenticationSessionModel authSession;
    private ECKey signingKey;

    @BeforeEach
    void setUp() throws Exception {
        config = mock(Oid4vpIdentityProviderConfig.class);
        provider = mock(Oid4vpIdentityProvider.class);
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.isIssuerAllowed(anyString())).thenReturn(true);
        when(config.isCredentialTypeAllowed(anyString())).thenReturn(true);
        when(config.getUserMappingClaimForFormat(anyString())).thenReturn("sub");
        when(config.getEffectiveTrustX5cFromCredential()).thenReturn(false);
        when(config.isSkipTrustListVerification()).thenReturn(true);

        Oid4vpResponseDecryptor responseDecryptor = new Oid4vpResponseDecryptor();
        VpTokenProcessor vpTokenProcessor = new VpTokenProcessor(new ObjectMapper());
        processor = new Oid4vpCallbackProcessor(config, provider, responseDecryptor, vpTokenProcessor);

        authSession = mock(AuthenticationSessionModel.class);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void process_validSdJwt_returnsBrokeredIdentityContext() throws Exception {
        String state = "test-state";
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn(state);
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("test-nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");

        String vpToken =
                buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user1")) + "~";

        BrokeredIdentityContext result = processor.process(authSession, state, vpToken, null, null, null);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("user1");
        assertThat(result.getContextData()).containsKey("oid4vp_claims");
        assertThat(result.getContextData().get("oid4vp_issuer")).isEqualTo("https://issuer.example");
        assertThat(result.getContextData().get("oid4vp_credential_type")).isEqualTo("IdentityCredential");
    }

    @Test
    void process_invalidState_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("expected-state");

        assertThatThrownBy(() -> processor.process(authSession, "wrong-state", "token", null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Invalid state");
    }

    @Test
    void process_nullExpectedState_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn(null);

        assertThatThrownBy(() -> processor.process(authSession, "any-state", "token", null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Invalid state");
    }

    @Test
    void process_walletError_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");

        assertThatThrownBy(() -> processor.process(authSession, "state", null, null, "access_denied", "User denied"))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("access_denied")
                .hasMessageContaining("User denied");
    }

    @Test
    void process_walletErrorWithoutDescription_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");

        assertThatThrownBy(() -> processor.process(authSession, "state", null, null, "access_denied", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("access_denied");
    }

    @Test
    void process_missingVpToken_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");

        assertThatThrownBy(() -> processor.process(authSession, "state", null, null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing vp_token");
    }

    @Test
    void process_issuerNotAllowed_throws() throws Exception {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");
        when(config.isIssuerAllowed("https://bad-issuer.example")).thenReturn(false);

        String vpToken =
                buildSdJwt(Map.of("iss", "https://bad-issuer.example", "vct", "IdentityCredential", "sub", "user1"))
                        + "~";

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken, null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Issuer not allowed");
    }

    @Test
    void process_credentialTypeNotAllowed_throws() throws Exception {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");
        when(config.isCredentialTypeAllowed("BadType")).thenReturn(false);

        String vpToken = buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "BadType", "sub", "user1")) + "~";

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken, null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Credential type not allowed");
    }

    @Test
    void process_missingSubjectClaim_throws() throws Exception {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");

        String vpToken = buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential")) + "~";

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken, null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing subject claim");
    }

    @Test
    void process_clearsSessionNotes() throws Exception {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");

        String vpToken =
                buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user1")) + "~";

        processor.process(authSession, "state", vpToken, null, null, null);

        verify(authSession).removeAuthNote(SESSION_STATE);
        verify(authSession).removeAuthNote(SESSION_NONCE);
        verify(authSession).removeAuthNote(SESSION_RESPONSE_URI);
        verify(authSession).removeAuthNote(SESSION_ENCRYPTION_KEY);
    }

    private String buildSdJwt(Map<String, Object> claimsMap) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        builder.expirationTime(Date.from(Instant.now().plusSeconds(3600)));

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }
}
