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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_MSO_MDOC;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_SD_JWT_VC;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.common.crypto.CryptoIntegration;

class Oid4vpCallbackProcessorTest {

    private static final Oid4vpRequestObjectStore.RequestContextEntry DEFAULT_REQUEST_CONTEXT =
            new Oid4vpRequestObjectStore.RequestContextEntry(
                    "handle-1",
                    "root-session",
                    "tab-1",
                    "test-state",
                    "test-client",
                    "https://example.com/callback",
                    "same_device",
                    "test-nonce",
                    null,
                    null);

    private Oid4vpCallbackProcessor processor;
    private Oid4vpIdentityProviderConfig config;
    private VpTokenProcessor vpTokenProcessor;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpCallbackProcessorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        config = mock(Oid4vpIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.isIssuerAllowed(anyString())).thenReturn(true);
        when(config.isCredentialTypeAllowed(anyString())).thenReturn(true);
        when(config.getUserMappingClaimForFormat(anyString())).thenReturn("sub");
        vpTokenProcessor = mock(VpTokenProcessor.class);
        UserAuthenticationIdentityProvider<?> provider = mock(UserAuthenticationIdentityProvider.class);
        processor = new Oid4vpCallbackProcessor(config, config, provider, vpTokenProcessor);
    }

    @Test
    void process_validSdJwt_returnsBrokeredIdentityContext() throws Exception {
        String vpToken = "vp-token";
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("sub", "user1"),
                PresentationType.SD_JWT);
        when(vpTokenProcessor.process(
                        vpToken,
                        DEFAULT_REQUEST_CONTEXT.effectiveClientId(),
                        DEFAULT_REQUEST_CONTEXT.nonce(),
                        DEFAULT_REQUEST_CONTEXT.responseUri(),
                        null,
                        null))
                .thenReturn(new VpTokenResult(Map.of("cred-1", credential), Map.of()));

        BrokeredIdentityContext result = processor.process(DEFAULT_REQUEST_CONTEXT, vpToken, null, null);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("user1");
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY);
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY))
                .isEqualTo("https://issuer.example");
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY))
                .isEqualTo("IdentityCredential");
    }

    @Test
    void process_missingRequestContext_throws() {
        assertThatThrownBy(() -> processor.process(null, "token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing request context");
    }

    @Test
    void process_missingVpToken_throws() {
        assertThatThrownBy(() -> processor.process(DEFAULT_REQUEST_CONTEXT, null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing vp_token");
    }

    @Test
    void process_issuerNotAllowed_throws() throws Exception {
        when(config.isIssuerAllowed("https://bad-issuer.example")).thenReturn(false);
        String vpToken = "vp-token";
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1",
                "https://bad-issuer.example",
                "IdentityCredential",
                Map.of("sub", "user1"),
                PresentationType.SD_JWT);
        when(vpTokenProcessor.process(vpToken, "test-client", "nonce", "https://example.com/callback", null, null))
                .thenReturn(new VpTokenResult(Map.of("cred-1", credential), Map.of()));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), vpToken, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Issuer not allowed");
    }

    @Test
    void process_credentialTypeNotAllowed_throws() throws Exception {
        when(config.isCredentialTypeAllowed("BadType")).thenReturn(false);
        String vpToken = "vp-token";
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1", "https://issuer.example", "BadType", Map.of("sub", "user1"), PresentationType.SD_JWT);
        when(vpTokenProcessor.process(vpToken, "test-client", "nonce", "https://example.com/callback", null, null))
                .thenReturn(new VpTokenResult(Map.of("cred-1", credential), Map.of()));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), vpToken, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Credential type not allowed");
    }

    @Test
    void process_missingSubjectClaim_throws() throws Exception {
        String vpToken = "vp-token";
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1", "https://issuer.example", "IdentityCredential", Map.of(), PresentationType.SD_JWT);
        when(vpTokenProcessor.process(vpToken, "test-client", "nonce", "https://example.com/callback", null, null))
                .thenReturn(new VpTokenResult(Map.of("cred-1", credential), Map.of()));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), vpToken, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing subject claim");
    }

    @Test
    void process_usesOnlyRequestContextState() throws Exception {
        String vpToken = "vp-token";
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("sub", "user1"),
                PresentationType.SD_JWT);
        when(vpTokenProcessor.process(
                        vpToken,
                        DEFAULT_REQUEST_CONTEXT.effectiveClientId(),
                        DEFAULT_REQUEST_CONTEXT.nonce(),
                        DEFAULT_REQUEST_CONTEXT.responseUri(),
                        null,
                        null))
                .thenReturn(new VpTokenResult(Map.of("cred-1", credential), Map.of()));

        BrokeredIdentityContext result = processor.process(DEFAULT_REQUEST_CONTEXT, vpToken, null, null);

        assertThat(result.getId()).isNotBlank();
    }

    @Test
    void process_withIdTokenSubject_usesJwkThumbprintAsSub() throws Exception {
        when(config.isUseIdTokenSubject()).thenReturn(true);
        when(config.getClockSkewSeconds()).thenReturn(30);

        // Use a mocked VpTokenProcessor to avoid KB-JWT requirement when clientId is set
        VerifiedCredential credential = new VerifiedCredential(
                "cred1",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("sub", "user1"),
                PresentationType.SD_JWT);
        when(vpTokenProcessor.process(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(new VpTokenResult(Map.of("cred1", credential), Map.of()));

        UserAuthenticationIdentityProvider<?> provider = mock(UserAuthenticationIdentityProvider.class);
        Oid4vpCallbackProcessor idTokenProcessor =
                new Oid4vpCallbackProcessor(config, config, provider, vpTokenProcessor);

        ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
        String idToken = buildSelfIssuedIdToken(walletKey, "test-client", "test-nonce");

        BrokeredIdentityContext result =
                idTokenProcessor.process(DEFAULT_REQUEST_CONTEXT, "dummy-vp-token", idToken, null);

        String expectedSub = walletKey.computeThumbprint("SHA-256").toString();
        String expectedIdentityKey = credential.generateIdentityKey(expectedSub);
        // BrokeredIdentityContext lowercases the username internally
        assertThat(result.getUsername()).isEqualToIgnoringCase(expectedSub);
        assertThat(result.getId()).isEqualTo(expectedIdentityKey);
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY))
                .isEqualTo(expectedSub);
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY);
    }

    @Test
    void process_claimMappedSubjectsMatchIgnoringCase() throws Exception {
        when(config.getUserMappingClaimForFormat(FORMAT_SD_JWT_VC)).thenReturn("family_name");
        when(config.getUserMappingClaimForFormat(FORMAT_MSO_MDOC)).thenReturn("eu.europa.ec.eudi.pid.1/family_name");

        VerifiedCredential sdJwtCredential = new VerifiedCredential(
                "sd-jwt-credential",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("family_name", "ExampleUser"),
                PresentationType.SD_JWT);
        VerifiedCredential mdocCredential = new VerifiedCredential(
                "mdoc-credential",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("eu.europa.ec.eudi.pid.1/family_name", "exampleuser"),
                PresentationType.MDOC);
        when(vpTokenProcessor.process(eq("vp-upper"), any(), anyString(), any(), any(), any()))
                .thenReturn(new VpTokenResult(Map.of("sd-jwt-credential", sdJwtCredential), Map.of()));
        when(vpTokenProcessor.process(eq("vp-lower"), any(), anyString(), any(), any(), any()))
                .thenReturn(new VpTokenResult(Map.of("mdoc-credential", mdocCredential), Map.of()));

        UserAuthenticationIdentityProvider<?> provider = mock(UserAuthenticationIdentityProvider.class);
        Oid4vpCallbackProcessor claimProcessor =
                new Oid4vpCallbackProcessor(config, config, provider, vpTokenProcessor);

        BrokeredIdentityContext upperResult =
                claimProcessor.process(requestContext("state-upper", "nonce-upper"), "vp-upper", null, null);
        BrokeredIdentityContext lowerResult =
                claimProcessor.process(requestContext("state-lower", "nonce-lower"), "vp-lower", null, null);

        assertThat(upperResult.getId()).isEqualTo(lowerResult.getId());
    }

    @Test
    void process_idTokenSubjectEnabled_noIdToken_throws() throws Exception {
        when(config.isUseIdTokenSubject()).thenReturn(true);

        // Use a mocked VpTokenProcessor to isolate the id_token validation test
        VerifiedCredential credential = new VerifiedCredential(
                "cred1",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("sub", "user1"),
                PresentationType.SD_JWT);
        when(vpTokenProcessor.process(anyString(), any(), anyString(), any(), any(), any()))
                .thenReturn(new VpTokenResult(Map.of("cred1", credential), Map.of()));

        UserAuthenticationIdentityProvider<?> provider = mock(UserAuthenticationIdentityProvider.class);
        Oid4vpCallbackProcessor idTokenProcessor =
                new Oid4vpCallbackProcessor(config, config, provider, vpTokenProcessor);

        assertThatThrownBy(() -> idTokenProcessor.process(DEFAULT_REQUEST_CONTEXT, "dummy-vp-token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("no id_token received");
    }

    // ===== Helper Methods =====

    private String buildSelfIssuedIdToken(ECKey walletKey, String audience, String nonce) throws Exception {
        String thumbprint = walletKey.computeThumbprint("SHA-256").toString();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(thumbprint)
                .subject(thumbprint)
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sub_jwk", walletKey.toPublicJWK().toJSONObject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(walletKey));
        return jwt.serialize();
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(String state, String nonce) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                state,
                "test-client",
                "https://example.com/callback",
                "same_device",
                nonce,
                null,
                null);
    }
}
