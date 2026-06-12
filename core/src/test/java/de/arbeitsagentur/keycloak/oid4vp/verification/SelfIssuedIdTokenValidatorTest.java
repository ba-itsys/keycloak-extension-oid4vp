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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class SelfIssuedIdTokenValidatorTest {

    private SelfIssuedIdTokenValidator validator;
    private ECKey walletKey;
    private String thumbprint;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SelfIssuedIdTokenValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        validator = new SelfIssuedIdTokenValidator(30);
        walletKey = new ECKeyGenerator(Curve.P_256).generate();
        thumbprint = walletKey.computeThumbprint("SHA-256").toString();
    }

    @Test
    void validate_validToken_returnsSub() throws Exception {
        String idToken = buildIdToken(walletKey, thumbprint, thumbprint, "client1", "nonce1", 300);

        String sub = validator.validate(idToken, "client1", "nonce1");

        assertThat(sub).isEqualTo(thumbprint);
    }

    @Test
    void validate_issuerSelfIssuedV2_returnsSub() throws Exception {
        String idToken = buildIdToken(walletKey, "https://self-issued.me/v2", thumbprint, "client1", "nonce1", 300);

        String sub = validator.validate(idToken, "client1", "nonce1");

        assertThat(sub).isEqualTo(thumbprint);
    }

    @Test
    void validate_wrongSignature_throws() throws Exception {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        // Build token with walletKey's sub_jwk but sign with a different key
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(thumbprint)
                .subject(thumbprint)
                .audience("client1")
                .claim("nonce", "nonce1")
                .claim("sub_jwk", walletKey.toPublicJWK().toJSONObject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(otherKey));

        String idToken = jwt.serialize();

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("signature verification failed");
    }

    @Test
    void validate_subDoesNotMatchThumbprint_throws() throws Exception {
        String idToken = buildIdToken(walletKey, "wrong-sub", "wrong-sub", "client1", "nonce1", 300);

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sub does not match JWK Thumbprint");
    }

    @Test
    void validate_wrongAudience_throws() throws Exception {
        String idToken = buildIdToken(walletKey, thumbprint, thumbprint, "wrong-client", "nonce1", 300);

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("aud does not contain expected audience");
    }

    @Test
    void validate_wrongNonce_throws() throws Exception {
        String idToken = buildIdToken(walletKey, thumbprint, thumbprint, "client1", "wrong-nonce", 300);

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nonce does not match");
    }

    @Test
    void validate_expired_throws() throws Exception {
        String idToken = buildIdToken(walletKey, thumbprint, thumbprint, "client1", "nonce1", -600);

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void validate_missingSubJwk_throws() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(thumbprint)
                .subject(thumbprint)
                .audience("client1")
                .claim("nonce", "nonce1")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(walletKey));

        assertThatThrownBy(() -> validator.validate(jwt.serialize(), "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing sub_jwk");
    }

    @Test
    void validate_invalidIssuer_throws() throws Exception {
        String idToken = buildIdToken(walletKey, "https://evil.example", thumbprint, "client1", "nonce1", 300);

        assertThatThrownBy(() -> validator.validate(idToken, "client1", "nonce1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("iss must equal sub");
    }

    @Test
    void validate_nullNonce_skipsNonceCheck() throws Exception {
        String idToken = buildIdToken(walletKey, thumbprint, thumbprint, "client1", "any-nonce", 300);

        String sub = validator.validate(idToken, "client1", null);

        assertThat(sub).isEqualTo(thumbprint);
    }

    private String buildIdToken(ECKey key, String issuer, String subject, String audience, String nonce, int expSeconds)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sub_jwk", key.toPublicJWK().toJSONObject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(expSeconds)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
