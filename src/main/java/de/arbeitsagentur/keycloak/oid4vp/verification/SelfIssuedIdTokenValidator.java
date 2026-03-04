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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SELF_ISSUED_V2;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Map;

/**
 * Validates Self-Issued ID Tokens per the SIOPv2 specification.
 *
 * <p>A Self-Issued ID Token is signed by the wallet's own key. The public key is embedded in the
 * {@code sub_jwk} claim, and the {@code sub} claim equals the JWK Thumbprint (SHA-256) of that key.
 * This validator verifies the signature, subject binding, audience, nonce, and time validity.
 *
 * @see <a href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">SIOPv2</a>
 */
public class SelfIssuedIdTokenValidator {

    private final int clockSkewSeconds;

    public SelfIssuedIdTokenValidator(int clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    /**
     * Validates a SIOPv2 Self-Issued ID Token and returns the {@code sub} claim.
     *
     * @param idTokenString the compact-serialized JWT
     * @param expectedAudience the client_id from the authorization request
     * @param expectedNonce the nonce from the authorization request
     * @return the validated {@code sub} claim (JWK Thumbprint of {@code sub_jwk})
     * @throws IllegalArgumentException if validation fails
     */
    public String validate(String idTokenString, String expectedAudience, String expectedNonce) {
        try {
            SignedJWT jwt = SignedJWT.parse(idTokenString);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            ECKey subJwk = extractSubJwk(claims);
            verifySignature(jwt, subJwk);
            String sub = verifySubjectBinding(claims, subJwk);
            verifyIssuer(claims, sub);
            verifyAudience(claims, expectedAudience);
            verifyNonce(claims, expectedNonce);
            verifyTimeValidity(claims);

            return sub;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to validate ID token: " + e.getMessage(), e);
        }
    }

    private ECKey extractSubJwk(JWTClaimsSet claims) throws Exception {
        Map<String, Object> subJwkMap = claims.getJSONObjectClaim("sub_jwk");
        if (subJwkMap == null) {
            throw new IllegalArgumentException("Missing sub_jwk claim in ID token");
        }
        JWK jwk = JWK.parse(subJwkMap);
        if (!(jwk instanceof ECKey ecKey)) {
            throw new IllegalArgumentException("sub_jwk must be an EC key");
        }
        return ecKey;
    }

    private void verifySignature(SignedJWT jwt, ECKey subJwk) throws Exception {
        JWSVerifier verifier = new ECDSAVerifier(subJwk);
        if (!jwt.verify(verifier)) {
            throw new IllegalArgumentException("ID token signature verification failed");
        }
    }

    private String verifySubjectBinding(JWTClaimsSet claims, ECKey subJwk) throws Exception {
        String sub = claims.getSubject();
        String expectedSub = subJwk.computeThumbprint("SHA-256").toString();
        if (sub == null || !sub.equals(expectedSub)) {
            throw new IllegalArgumentException("ID token sub does not match JWK Thumbprint of sub_jwk");
        }
        return sub;
    }

    private void verifyIssuer(JWTClaimsSet claims, String sub) {
        String iss = claims.getIssuer();
        if (!sub.equals(iss) && !SELF_ISSUED_V2.equals(iss)) {
            throw new IllegalArgumentException("ID token iss must equal sub or be " + SELF_ISSUED_V2);
        }
    }

    private void verifyAudience(JWTClaimsSet claims, String expectedAudience) {
        if (!claims.getAudience().contains(expectedAudience)) {
            throw new IllegalArgumentException("ID token aud does not contain expected audience: " + expectedAudience);
        }
    }

    private void verifyNonce(JWTClaimsSet claims, String expectedNonce) throws Exception {
        if (expectedNonce == null) return;
        String nonce = claims.getStringClaim("nonce");
        if (!expectedNonce.equals(nonce)) {
            throw new IllegalArgumentException("ID token nonce does not match expected nonce");
        }
    }

    private void verifyTimeValidity(JWTClaimsSet claims) {
        Instant now = Instant.now();
        if (claims.getExpirationTime() != null) {
            Instant exp = claims.getExpirationTime().toInstant().plusSeconds(clockSkewSeconds);
            if (now.isAfter(exp)) {
                throw new IllegalArgumentException("ID token is expired");
            }
        }
        if (claims.getIssueTime() != null) {
            Instant iat = claims.getIssueTime().toInstant().minusSeconds(clockSkewSeconds);
            if (now.isBefore(iat)) {
                throw new IllegalArgumentException("ID token issued in the future");
            }
        }
    }
}
