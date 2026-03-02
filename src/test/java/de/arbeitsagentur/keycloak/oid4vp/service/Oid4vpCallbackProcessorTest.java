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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.verification.StatusListVerifier;
import de.arbeitsagentur.keycloak.oid4vp.verification.TrustListProvider;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.sessions.AuthenticationSessionModel;

class Oid4vpCallbackProcessorTest {

    private Oid4vpCallbackProcessor processor;
    private Oid4vpIdentityProviderConfig config;
    private AuthenticationSessionModel authSession;
    private ECKey signingKey;
    private X509Certificate signingCert;

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
        authSession = mock(AuthenticationSessionModel.class);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        signingCert = generateSelfSignedCert(signingKey);

        TrustListProvider trustListProvider = new TrustListProvider(List.of(signingCert));
        VpTokenProcessor vpTokenProcessor =
                new VpTokenProcessor(new ObjectMapper(), new StatusListVerifier(), trustListProvider);
        UserAuthenticationIdentityProvider<?> provider = mock(UserAuthenticationIdentityProvider.class);
        processor = new Oid4vpCallbackProcessor(config, config, provider, vpTokenProcessor);
    }

    @Test
    void process_validSdJwt_returnsBrokeredIdentityContext() throws Exception {
        String state = "test-state";
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn(state);
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("test-nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");

        String vpToken =
                buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user1")) + "~";

        BrokeredIdentityContext result = processor.process(authSession, state, vpToken);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("user1");
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY);
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY))
                .isEqualTo("https://issuer.example");
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY))
                .isEqualTo("IdentityCredential");
    }

    @Test
    void process_invalidState_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("expected-state");

        assertThatThrownBy(() -> processor.process(authSession, "wrong-state", "token"))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Invalid state");
    }

    @Test
    void process_nullExpectedState_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn(null);

        assertThatThrownBy(() -> processor.process(authSession, "any-state", "token"))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Invalid state");
    }

    @Test
    void process_missingVpToken_throws() {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");

        assertThatThrownBy(() -> processor.process(authSession, "state", null))
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

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken))
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

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Credential type not allowed");
    }

    @Test
    void process_missingSubjectClaim_throws() throws Exception {
        when(authSession.getAuthNote(SESSION_STATE)).thenReturn("state");
        when(authSession.getAuthNote(SESSION_NONCE)).thenReturn("nonce");
        when(authSession.getAuthNote(SESSION_RESPONSE_URI)).thenReturn("https://example.com/callback");

        String vpToken = buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential")) + "~";

        assertThatThrownBy(() -> processor.process(authSession, "state", vpToken))
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

        processor.process(authSession, "state", vpToken);

        verify(authSession).removeAuthNote(SESSION_STATE);
        verify(authSession).removeAuthNote(SESSION_NONCE);
        verify(authSession).removeAuthNote(SESSION_RESPONSE_URI);
        verify(authSession).removeAuthNote(SESSION_CLIENT_ID);
    }

    // ===== Helper Methods =====

    private JWSHeader buildHeaderWithX5c() throws Exception {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(signingCert.getEncoded())))
                .build();
    }

    private String buildSdJwt(Map<String, Object> claimsMap) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        Instant now = Instant.now();
        builder.issueTime(Date.from(now));
        builder.notBeforeTime(Date.from(now));
        builder.expirationTime(Date.from(now.plusSeconds(3600)));

        SignedJWT signedJWT = new SignedJWT(buildHeaderWithX5c(), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal("CN=Test SD-JWT Issuer");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                publicKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.toECPrivateKey());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
