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

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
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
import org.keycloak.common.crypto.CryptoIntegration;

class SdJwtVerifierTest {

    private SdJwtVerifier verifier;
    private ECKey signingKey;
    private X509Certificate signingCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtVerifierTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        verifier = new SdJwtVerifier(60, 300);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        signingCert = generateSelfSignedCert(signingKey);
    }

    @Test
    void isSdJwt_withTilde_returnsTrue() {
        assertThat(verifier.isSdJwt("header.payload.sig~disclosure1~")).isTrue();
    }

    @Test
    void isSdJwt_withoutTilde_returnsFalse() {
        assertThat(verifier.isSdJwt("header.payload.sig")).isFalse();
    }

    @Test
    void isSdJwt_null_returnsFalse() {
        assertThat(verifier.isSdJwt(null)).isFalse();
    }

    @Test
    void verify_validSdJwt_extractsClaims() throws Exception {
        String jwt =
                buildSignedJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user123"));
        String sdJwt = jwt + "~";

        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(signingCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.credentialType()).isEqualTo("IdentityCredential");
        assertThat(result.claims()).containsEntry("sub", "user123");
    }

    @Test
    void verify_expiredJwt_throws() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .issueTime(Date.from(Instant.now().minusSeconds(7200)))
                .notBeforeTime(Date.from(Instant.now().minusSeconds(7200)))
                .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
                .build();
        SignedJWT signedJWT = new SignedJWT(buildHeaderWithX5c(), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        String sdJwt = signedJWT.serialize() + "~";

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void verify_noKeyMaterial_throws() throws Exception {
        String jwt = buildSignedJwt(Map.of("iss", "test"));
        String sdJwt = jwt + "~";

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No trusted keys available");
    }

    @Test
    void verify_withDisclosures_mergesClaims() throws Exception {
        // Build a disclosure: [salt, claimName, claimValue]
        String disclosureJson = "[\"salt123\",\"given_name\",\"John\"]";
        String disclosureB64 =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

        // Compute disclosure digest
        String digest = computeDigest(disclosureB64);

        String jwt = buildSignedJwt(Map.of(
                "iss", "https://issuer.example",
                "vct", "IdentityCredential",
                "_sd", List.of(digest),
                "_sd_alg", "sha-256"));
        String sdJwt = jwt + "~" + disclosureB64 + "~";

        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(signingCert));

        assertThat(result.claims()).containsEntry("given_name", "John");
        assertThat(result.claims()).doesNotContainKey("_sd");
        assertThat(result.claims()).doesNotContainKey("_sd_alg");
    }

    @Test
    void verify_disclosureNotInSdArray_throws() throws Exception {
        String disclosureJson = "[\"salt123\",\"given_name\",\"John\"]";
        String disclosureB64 =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

        // Use a _sd array that does NOT contain this disclosure's digest
        String jwt = buildSignedJwt(Map.of(
                "iss", "https://issuer.example",
                "_sd", List.of("wrong_digest"),
                "_sd_alg", "sha-256"));
        String sdJwt = jwt + "~" + disclosureB64 + "~";

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class);
    }

    @SuppressWarnings("unchecked")
    @Test
    void verify_nestedDisclosures_resolvesAddressSubClaims() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        // Build nested disclosures like the EUDI PID: address has its own _sd array
        String localityDisclosure = "[\"salt1\",\"locality\",\"BERLIN\"]";
        String localityB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(localityDisclosure.getBytes(StandardCharsets.UTF_8));
        String localityDigest = computeDigest(localityB64);

        String streetDisclosure = "[\"salt2\",\"street_address\",\"HAUPTSTR 1\"]";
        String streetB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(streetDisclosure.getBytes(StandardCharsets.UTF_8));
        String streetDigest = computeDigest(streetB64);

        // address disclosure reveals an object with its own _sd array
        String addressObj = objectMapper.writeValueAsString(Map.of("_sd", List.of(localityDigest, streetDigest)));
        String addressDisclosure = "[\"salt3\",\"address\"," + addressObj + "]";
        String addressB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(addressDisclosure.getBytes(StandardCharsets.UTF_8));
        String addressDigest = computeDigest(addressB64);

        String givenNameDisclosure = "[\"salt4\",\"given_name\",\"ERIKA\"]";
        String givenNameB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(givenNameDisclosure.getBytes(StandardCharsets.UTF_8));
        String givenNameDigest = computeDigest(givenNameB64);

        String jwt = buildSignedJwt(Map.of(
                "iss", "https://issuer.example",
                "vct", "urn:eudi:pid:de:1",
                "_sd", List.of(addressDigest, givenNameDigest),
                "_sd_alg", "sha-256"));

        String sdJwt = jwt + "~" + givenNameB64 + "~" + addressB64 + "~" + localityB64 + "~" + streetB64 + "~";

        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(signingCert));

        assertThat(result.claims()).containsEntry("given_name", "ERIKA");
        assertThat(result.claims()).containsKey("address");
        Map<String, Object> address = (Map<String, Object>) result.claims().get("address");
        assertThat(address).containsEntry("locality", "BERLIN");
        assertThat(address).containsEntry("street_address", "HAUPTSTR 1");
        assertThat(address).doesNotContainKey("_sd");
    }

    @Test
    void verify_oldCredentialWithFreshKbJwt_succeeds() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        // Credential issued 2 hours ago — well beyond the 300s KB-JWT max age
        Instant issuedAt = Instant.now().minusSeconds(7200);
        String credJwt = buildSignedJwtAt(
                Map.of(
                        "iss", "https://issuer.example",
                        "vct", "IdentityCredential",
                        "sub", "user123",
                        "cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject())),
                issuedAt);

        String sdJwt =
                buildSdJwtVpWithKbJwt(credJwt, holderKey, "https://verifier.example", "test-nonce", Instant.now());

        SdJwtVerificationResult result =
                verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.claims()).containsEntry("sub", "user123");
    }

    @Test
    void verify_validKbJwt_succeeds() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss", "https://issuer.example",
                "vct", "IdentityCredential",
                "cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        String sdJwt =
                buildSdJwtVpWithKbJwt(credJwt, holderKey, "https://verifier.example", "test-nonce", Instant.now());

        SdJwtVerificationResult result =
                verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
    }

    @Test
    void verify_staleKbJwt_throws() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss",
                "https://issuer.example",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        // KB-JWT issued 10 minutes ago — beyond the 300s + 60s skew max age
        Instant staleIat = Instant.now().minusSeconds(600);
        String sdJwt = buildSdJwtVpWithKbJwt(credJwt, holderKey, "https://verifier.example", "test-nonce", staleIat);

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired by iat");
    }

    @Test
    void verify_kbJwtMissingCnfJwk_throws() throws Exception {
        // Build credential JWT without cnf
        String credJwt = buildSignedJwt(Map.of("iss", "https://issuer.example"));

        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        String sdJwt =
                buildSdJwtVpWithKbJwt(credJwt, holderKey, "https://verifier.example", "test-nonce", Instant.now());

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void verify_kbJwtAudienceMismatch_throws() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss",
                "https://issuer.example",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        String sdJwt = buildSdJwtVpWithKbJwt(
                credJwt, holderKey, "https://wrong-audience.example", "test-nonce", Instant.now());

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void verify_kbJwtNonceMismatch_throws() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss",
                "https://issuer.example",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        String sdJwt =
                buildSdJwtVpWithKbJwt(credJwt, holderKey, "https://verifier.example", "wrong-nonce", Instant.now());

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void verify_x5cChainWithCaTrust_succeeds() throws Exception {
        // CA key + cert
        ECKey caKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate caCert = generateSelfSignedCert(caKey, "CN=Test CA");

        // End-entity key + cert signed by CA
        ECKey entityKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate entityCert = generateCaSignedCert(entityKey, caKey, caCert, "CN=Test Issuer");

        // Sign SD-JWT with entity key, x5c = [entityCert]
        String jwt = buildSignedJwtWithKey(
                Map.of("iss", "https://issuer.example", "vct", "PID"), entityKey, List.of(entityCert));
        String sdJwt = jwt + "~";

        // Trust list only has the CA cert
        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(caCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.credentialType()).isEqualTo("PID");
    }

    @Test
    void verify_x5cChainWithFullChain_succeeds() throws Exception {
        // CA key + cert
        ECKey caKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate caCert = generateSelfSignedCert(caKey, "CN=Test CA");

        // End-entity key + cert signed by CA
        ECKey entityKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate entityCert = generateCaSignedCert(entityKey, caKey, caCert, "CN=Test Issuer");

        // Sign SD-JWT with entity key, x5c = [entityCert, caCert]
        String jwt = buildSignedJwtWithKey(
                Map.of("iss", "https://issuer.example", "vct", "PID"), entityKey, List.of(entityCert, caCert));
        String sdJwt = jwt + "~";

        // Trust list only has the CA cert
        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(caCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
    }

    @Test
    void verify_x5cChainUntrustedCa_throws() throws Exception {
        // CA key + cert (not in trust list)
        ECKey caKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate caCert = generateSelfSignedCert(caKey, "CN=Untrusted CA");

        // End-entity key + cert signed by untrusted CA
        ECKey entityKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate entityCert = generateCaSignedCert(entityKey, caKey, caCert, "CN=Test Issuer");

        // Different CA in trust list
        ECKey trustedCaKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate trustedCaCert = generateSelfSignedCert(trustedCaKey, "CN=Trusted CA");

        String jwt = buildSignedJwtWithKey(
                Map.of("iss", "https://issuer.example", "vct", "PID"), entityKey, List.of(entityCert));
        String sdJwt = jwt + "~";

        // Neither the x5c chain nor direct key matching should work
        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, List.of(trustedCaCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Signature could not be verified");
    }

    // ===== Helper Methods =====

    private String computeDigest(String disclosureB64) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA256");
        byte[] hash = md.digest(disclosureB64.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private JWSHeader buildHeaderWithX5c() throws Exception {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(signingCert.getEncoded())))
                .build();
    }

    private String buildSignedJwt(Map<String, Object> claimsMap) throws Exception {
        return buildSignedJwtAt(claimsMap, Instant.now());
    }

    private String buildSignedJwtAt(Map<String, Object> claimsMap, Instant issuedAt) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        builder.issueTime(Date.from(issuedAt));
        builder.notBeforeTime(Date.from(issuedAt));
        builder.expirationTime(Date.from(issuedAt.plusSeconds(86400)));

        SignedJWT signedJWT = new SignedJWT(buildHeaderWithX5c(), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }

    private String buildSdJwtVpWithKbJwt(String credJwt, ECKey holderKey, String audience, String nonce, Instant kbIat)
            throws Exception {
        // The unbound presentation is: issuerJwt~
        String unboundPresentation = credJwt + "~";

        // sd_hash = base64url(SHA-256(unbound_presentation))
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(unboundPresentation.getBytes(StandardCharsets.US_ASCII));
        String sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .issueTime(Date.from(kbIat))
                .build();
        SignedJWT kbJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                kbClaims);
        kbJwt.sign(new ECDSASigner(holderKey));

        return unboundPresentation + kbJwt.serialize();
    }

    private String buildSignedJwtWithKey(Map<String, Object> claimsMap, ECKey key, List<X509Certificate> x5cCerts)
            throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        Instant now = Instant.now();
        builder.issueTime(Date.from(now));
        builder.notBeforeTime(Date.from(now));
        builder.expirationTime(Date.from(now.plusSeconds(86400)));

        List<com.nimbusds.jose.util.Base64> x5cB64 = x5cCerts.stream()
                .map(c -> {
                    try {
                        return com.nimbusds.jose.util.Base64.encode(c.getEncoded());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .toList();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).x509CertChain(x5cB64).build();
        SignedJWT signedJWT = new SignedJWT(header, builder.build());
        signedJWT.sign(new ECDSASigner(key));
        return signedJWT.serialize();
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        return generateSelfSignedCert(ecKey, "CN=Test SD-JWT Issuer");
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey, String dn) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal(dn);
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

    private static X509Certificate generateCaSignedCert(
            ECKey subjectKey, ECKey caKey, X509Certificate caCert, String dn) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCert.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis() + 1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Principal(dn),
                subjectKey.toECPublicKey());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKey.toECPrivateKey());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
