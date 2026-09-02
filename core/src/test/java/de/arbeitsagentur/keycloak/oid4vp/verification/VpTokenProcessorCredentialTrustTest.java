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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.trust.CredentialTrustPlan;
import de.arbeitsagentur.keycloak.oid4vp.trust.FixedTrustMaterialIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.trust.TestTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TrustedIssuerKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;

/**
 * Trust selection per credential: a presentation is verified against the trust material of the
 * providers serving the credential type requested under the id the wallet answered with.
 */
class VpTokenProcessorCredentialTrustTest {

    private static final String PID_TYPE = "urn:eudi:pid:1";
    private static final String BADGE_TYPE = "https://kc.example/badge";
    private static final String BADGE_ISSUER = "https://kc.example/realms/company";
    private static final String CLIENT_ID = "client-id";
    private static final String NONCE = "nonce";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private ECKey pidIssuerKey;
    private X509Certificate pidIssuerCert;
    private ECKey badgeIssuerKey;
    private X509Certificate badgeIssuerCert;
    private ECKey holderKey;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(VpTokenProcessorCredentialTrustTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        pidIssuerKey = new ECKeyGenerator(Curve.P_256).generate();
        pidIssuerCert = selfSignedCertificate(pidIssuerKey, "CN=PID Issuer");
        badgeIssuerKey = new ECKeyGenerator(Curve.P_256).generate();
        badgeIssuerCert = selfSignedCertificate(badgeIssuerKey, "CN=Keycloak Realm Key");
        holderKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void everyCredentialIsVerifiedAgainstTheTrustDomainServingItsType() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());

        String vpToken = objectMapper.writeValueAsString(Map.of(
                "pid", presentation(pidIssuerKey, pidIssuerCert, "https://pid.example", PID_TYPE),
                "badge", presentation(badgeIssuerKey, null, BADGE_ISSUER, BADGE_TYPE)));

        VpTokenResult result = processor.process(request(vpToken, requestedCredentials()));

        assertThat(result.credentials()).containsOnlyKeys("pid", "badge");
        assertThat(result.credentials().get("pid").credentialType()).isEqualTo(PID_TYPE);
        assertThat(result.credentials().get("badge").credentialType()).isEqualTo(BADGE_TYPE);
    }

    @Test
    void aCredentialOfOneTrustDomainIsNotAcceptedUnderTheIdOfAnother() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());

        // The badge issuer signs a credential and the wallet answers with it under the PID id.
        String credential = presentation(badgeIssuerKey, badgeIssuerCert, BADGE_ISSUER, PID_TYPE);

        String underPidId = objectMapper.writeValueAsString(Map.of("pid", credential));
        assertThatThrownBy(() -> processor.process(request(underPidId, requestedCredentials())))
                .isInstanceOf(IdentityBrokerException.class);

        String underBadgeId = objectMapper.writeValueAsString(Map.of("badge", credential));
        assertThat(processor
                        .process(request(underBadgeId, requestedCredentials()))
                        .credentials())
                .as("the very same credential verifies under the id whose trust domain issued it")
                .containsOnlyKeys("badge");
    }

    @Test
    void aCredentialIdThatWasNotRequestedIsRejectedBeforeVerification() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());

        String vpToken = objectMapper.writeValueAsString(
                Map.of("unrequested", presentation(pidIssuerKey, pidIssuerCert, "https://pid.example", PID_TYPE)));

        assertThatThrownBy(() -> processor.process(request(vpToken, requestedCredentials())))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("was not requested");
    }

    @Test
    void aBareVpTokenIsAttributedToTheOnlyRequestedCredential() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());

        String vpToken = presentation(badgeIssuerKey, null, BADGE_ISSUER, BADGE_TYPE);
        VpTokenResult result = processor.process(request(
                vpToken, List.of(new RequestedCredential("badge", "dc+sd-jwt", BADGE_TYPE, List.of(), List.of()))));

        assertThat(result.credentials()).containsOnlyKeys("badge");
    }

    @Test
    void aChainlessCredentialIsVerifiedAgainstTheDirectlyTrustedRealmCertificate() throws Exception {
        CredentialTrustPlan plan = new CredentialTrustPlan(List.of(
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(badgeIssuerCert), BADGE_TYPE)));
        VpTokenProcessor processor = processor(plan);

        String vpToken = objectMapper.writeValueAsString(
                Map.of("badge", presentation(badgeIssuerKey, null, BADGE_ISSUER, BADGE_TYPE)));

        VpTokenResult result = processor.process(request(
                vpToken, List.of(new RequestedCredential("badge", "dc+sd-jwt", BADGE_TYPE, List.of(), List.of()))));

        assertThat(result.credentials()).containsOnlyKeys("badge");
    }

    @Test
    void anIssuerKeyOnlyVerifiesCredentialsOfTheIssuerItIsTrustedFor() throws Exception {
        JWK badgeJwk = toJwk(badgeIssuerKey, "realm-key-1");
        CredentialTrustPlan plan = new CredentialTrustPlan(List.of(FixedTrustMaterialIdentityProvider.serving(
                TestTrust.ofIssuerKeys(new TrustedIssuerKey(BADGE_ISSUER, badgeJwk)), BADGE_TYPE)));
        VpTokenProcessor processor = processor(plan);
        List<RequestedCredential> requested =
                List.of(new RequestedCredential("badge", "dc+sd-jwt", BADGE_TYPE, List.of(), List.of()));

        String trusted = objectMapper.writeValueAsString(
                Map.of("badge", presentation(badgeIssuerKey, null, BADGE_ISSUER, BADGE_TYPE, "realm-key-1")));
        assertThat(processor.process(request(trusted, requested)).credentials()).containsOnlyKeys("badge");

        String foreignIssuer = objectMapper.writeValueAsString(Map.of(
                "badge",
                presentation(badgeIssuerKey, null, "https://evil.example/realms/company", BADGE_TYPE, "realm-key-1")));
        assertThatThrownBy(() -> processor.process(request(foreignIssuer, requested)))
                .as("the same key must not verify a credential claiming another issuer")
                .isInstanceOf(IdentityBrokerException.class);
    }

    // --- one credential id requested with several types -------------------------

    @Test
    void anIdRequestedWithSeveralTypesJudgesThePresentationByTheTrustDomainOfTheTypeItNames() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());
        List<RequestedCredential> requested = List.of(
                new RequestedCredential("any", "dc+sd-jwt", List.of(PID_TYPE, BADGE_TYPE), List.of(), List.of()));

        String badge = objectMapper.writeValueAsString(
                Map.of("any", presentation(badgeIssuerKey, badgeIssuerCert, BADGE_ISSUER, BADGE_TYPE)));
        assertThat(processor
                        .process(request(badge, requested))
                        .credentials()
                        .get("any")
                        .credentialType())
                .isEqualTo(BADGE_TYPE);

        String pid = objectMapper.writeValueAsString(
                Map.of("any", presentation(pidIssuerKey, pidIssuerCert, "https://pid.example", PID_TYPE)));
        assertThat(processor
                        .process(request(pid, requested))
                        .credentials()
                        .get("any")
                        .credentialType())
                .isEqualTo(PID_TYPE);
    }

    @Test
    void anIdRequestedWithSeveralTypesDoesNotLendOneTypeTheTrustDomainOfAnother() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());
        List<RequestedCredential> requested = List.of(
                new RequestedCredential("any", "dc+sd-jwt", List.of(PID_TYPE, BADGE_TYPE), List.of(), List.of()));

        // The badge issuer signs a credential claiming to be a PID.
        String vpToken = objectMapper.writeValueAsString(
                Map.of("any", presentation(badgeIssuerKey, badgeIssuerCert, BADGE_ISSUER, PID_TYPE)));

        assertThatThrownBy(() -> processor.process(request(vpToken, requested)))
                .as("the PID type selects the PID trust domain, which does not know the badge issuer")
                .isInstanceOf(IdentityBrokerException.class);
    }

    @Test
    void aTypeNotRequestedUnderTheIdIsRejectedBeforeVerification() throws Exception {
        VpTokenProcessor processor = processor(twoTrustDomains());
        List<RequestedCredential> requested = List.of(
                new RequestedCredential("any", "dc+sd-jwt", List.of(PID_TYPE, BADGE_TYPE), List.of(), List.of()));

        String vpToken = objectMapper.writeValueAsString(
                Map.of("any", presentation(pidIssuerKey, pidIssuerCert, "https://pid.example", "urn:eudi:diploma:1")));

        assertThatThrownBy(() -> processor.process(request(vpToken, requested)))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("urn:eudi:diploma:1")
                .hasMessageContaining("none of the requested types");
    }

    private CredentialTrustPlan twoTrustDomains() {
        return new CredentialTrustPlan(List.of(
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(pidIssuerCert), PID_TYPE),
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(badgeIssuerCert), BADGE_TYPE)));
    }

    private static List<RequestedCredential> requestedCredentials() {
        return List.of(
                new RequestedCredential("pid", "dc+sd-jwt", PID_TYPE, List.of(), List.of()),
                new RequestedCredential("badge", "dc+sd-jwt", BADGE_TYPE, List.of(), List.of()));
    }

    private VpTokenProcessor processor(CredentialTrustPlan plan) {
        return new VpTokenProcessor(objectMapper, new StatusListVerifier(), () -> plan);
    }

    private static VpTokenProcessor.Request request(String vpToken, List<RequestedCredential> requestedCredentials) {
        return new VpTokenProcessor.Request(vpToken, CLIENT_ID, NONCE, null, null, null, requestedCredentials);
    }

    private String presentation(ECKey issuerKey, X509Certificate issuerCert, String issuer, String credentialType)
            throws Exception {
        return presentation(issuerKey, issuerCert, issuer, credentialType, null);
    }

    /** An SD-JWT VP without disclosures: the issuer signed JWT plus a key binding JWT. */
    private String presentation(
            ECKey issuerKey, X509Certificate issuerCert, String issuer, String credentialType, String keyId)
            throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256);
        if (issuerCert != null) {
            header.x509CertChain(List.of(Base64.encode(issuerCert.getEncoded())));
        }
        if (keyId != null) {
            header.keyID(keyId);
        }
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("iss", issuer)
                .claim("vct", credentialType)
                .claim("sub", "user1")
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .build();
        SignedJWT issuerSignedJwt = new SignedJWT(header.build(), claims);
        issuerSignedJwt.sign(new ECDSASigner(issuerKey));

        String unbound = issuerSignedJwt.serialize() + "~";
        byte[] sdHash = MessageDigest.getInstance("SHA-256").digest(unbound.getBytes(StandardCharsets.US_ASCII));
        SignedJWT keyBindingJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(CLIENT_ID)
                        .claim("nonce", NONCE)
                        .claim("sd_hash", Base64URL.encode(sdHash).toString())
                        .issueTime(new Date())
                        .build());
        keyBindingJwt.sign(new ECDSASigner(holderKey));
        return unbound + keyBindingJwt.serialize();
    }

    private static JWK toJwk(ECKey key, String keyId) throws Exception {
        JWK jwk = JWKBuilder.create().kid(keyId).ec(key.toECPublicKey(), KeyUse.SIG);
        jwk.setAlgorithm(JWSAlgorithm.ES256.getName());
        return jwk;
    }

    private static X509Certificate selfSignedCertificate(ECKey key, String subject) throws Exception {
        ECPublicKey publicKey = key.toECPublicKey();
        X500Principal principal = new X500Principal(subject);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                principal,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                principal,
                publicKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(key.toECPrivateKey());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
