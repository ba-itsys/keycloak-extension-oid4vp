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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SdJwtVerifierTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private SdJwtVerifier verifier;
    private ECKey signingKey;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new SdJwtVerifier(objectMapper);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
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
    void verify_validSdJwt_skipSig_extractsClaims() throws Exception {
        String jwt =
                buildSignedJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user123"));
        String sdJwt = jwt + "~";

        SdJwtVerifier.VerificationResult result = verifier.verify(sdJwt, null, null, false, true);

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.credentialType()).isEqualTo("IdentityCredential");
        assertThat(result.claims()).containsEntry("sub", "user123");
    }

    @Test
    void verify_expiredJwt_throws() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        signedJWT.sign(new ECDSASigner(signingKey));
        String sdJwt = signedJWT.serialize() + "~";

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void verify_noKeyMaterial_throws() throws Exception {
        String jwt = buildSignedJwt(Map.of("iss", "test"));
        String sdJwt = jwt + "~";

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, false, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No key material available");
    }

    @Test
    void verify_withDisclosures_mergesClaims() throws Exception {
        // Build a disclosure: [salt, claimName, claimValue]
        String disclosureJson = "[\"salt123\",\"given_name\",\"John\"]";
        String disclosureB64 =
                Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

        // Compute disclosure digest
        MessageDigest md = MessageDigest.getInstance("SHA256");
        byte[] hash = md.digest(disclosureB64.getBytes(StandardCharsets.US_ASCII));
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        String jwt = buildSignedJwt(Map.of(
                "iss", "https://issuer.example",
                "vct", "IdentityCredential",
                "_sd", List.of(digest),
                "_sd_alg", "sha-256"));
        String sdJwt = jwt + "~" + disclosureB64 + "~";

        SdJwtVerifier.VerificationResult result = verifier.verify(sdJwt, null, null, false, true);

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

        assertThatThrownBy(() -> verifier.verify(sdJwt, null, null, false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Disclosure digest not found in _sd array");
    }

    @Test
    void verify_kbJwtMissingCnfJwk_throws() throws Exception {
        // Build credential JWT without cnf
        String credJwt = buildSignedJwt(Map.of("iss", "https://issuer.example"));

        // Build a KB-JWT
        ECKey kbKey = new ECKeyGenerator(Curve.P_256).generate();
        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience("https://verifier.example")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .build();
        SignedJWT kbJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), kbClaims);
        kbJwt.sign(new ECDSASigner(kbKey));

        String sdJwt = credJwt + "~" + kbJwt.serialize();

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cnf.jwk missing");
    }

    @Test
    void verify_kbJwtAudienceMismatch_throws() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss",
                "https://issuer.example",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience("https://wrong-audience.example")
                .claim("nonce", "test-nonce")
                .issueTime(new Date())
                .build();
        SignedJWT kbJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), kbClaims);
        kbJwt.sign(new ECDSASigner(holderKey));

        String sdJwt = credJwt + "~" + kbJwt.serialize();

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("audience mismatch");
    }

    @Test
    void verify_kbJwtNonceMismatch_throws() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        String credJwt = buildSignedJwt(Map.of(
                "iss",
                "https://issuer.example",
                "cnf",
                Map.of("jwk", holderKey.toPublicJWK().toJSONObject())));

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .audience("https://verifier.example")
                .claim("nonce", "wrong-nonce")
                .issueTime(new Date())
                .build();
        SignedJWT kbJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), kbClaims);
        kbJwt.sign(new ECDSASigner(holderKey));

        String sdJwt = credJwt + "~" + kbJwt.serialize();

        assertThatThrownBy(() -> verifier.verify(sdJwt, "https://verifier.example", "test-nonce", false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("nonce mismatch");
    }

    @Test
    void split_parsesCorrectly() {
        SdJwtVerifier.SdJwtParts parts = SdJwtVerifier.split("jwt~disc1~disc2~");
        assertThat(parts.signedJwt()).isEqualTo("jwt");
        assertThat(parts.disclosures()).containsExactly("disc1", "disc2");
        assertThat(parts.keyBindingJwt()).isNull();
    }

    @Test
    void split_withKeyBindingJwt() {
        SdJwtVerifier.SdJwtParts parts = SdJwtVerifier.split("jwt~disc1~kbjwt");
        assertThat(parts.signedJwt()).isEqualTo("jwt");
        assertThat(parts.disclosures()).containsExactly("disc1");
        assertThat(parts.keyBindingJwt()).isEqualTo("kbjwt");
    }

    private String buildSignedJwt(Map<String, Object> claimsMap) throws Exception {
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
