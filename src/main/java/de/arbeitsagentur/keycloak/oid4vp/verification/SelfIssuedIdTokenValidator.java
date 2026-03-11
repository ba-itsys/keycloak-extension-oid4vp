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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.keycloak.jose.jws.JWSInput;

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

    public String validate(String idTokenString, String expectedAudience, String expectedNonce) {
        try {
            JWSInput jwt = X5cChainValidator.parseJwt(idTokenString);
            Map<String, Object> claims = X5cChainValidator.parseClaims(jwt);
            Oid4vpJwk subJwk = extractSubJwk(claims);
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

    @SuppressWarnings("unchecked")
    private Oid4vpJwk extractSubJwk(Map<String, Object> claims) {
        Object value = claims.get("sub_jwk");
        Map<String, Object> subJwkMap = value instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
        if (subJwkMap == null) {
            throw new IllegalArgumentException("Missing sub_jwk claim in ID token");
        }
        return Oid4vpJwk.parse(subJwkMap);
    }

    private void verifySignature(JWSInput jwt, Oid4vpJwk subJwk) throws Exception {
        X5cChainValidator.verifyJwtSignature(jwt, subJwk.toPublicKey());
    }

    private String verifySubjectBinding(Map<String, Object> claims, Oid4vpJwk subJwk) {
        String sub = stringClaim(claims, "sub");
        String expectedSub = subJwk.thumbprint();
        if (sub == null || !sub.equals(expectedSub)) {
            throw new IllegalArgumentException("ID token sub does not match JWK Thumbprint of sub_jwk");
        }
        return sub;
    }

    private void verifyIssuer(Map<String, Object> claims, String sub) {
        String iss = stringClaim(claims, "iss");
        if (!sub.equals(iss) && !SELF_ISSUED_V2.equals(iss)) {
            throw new IllegalArgumentException("ID token iss must equal sub or be " + SELF_ISSUED_V2);
        }
    }

    private void verifyAudience(Map<String, Object> claims, String expectedAudience) {
        List<String> audience = audience(claims);
        if (!audience.contains(expectedAudience)) {
            throw new IllegalArgumentException("ID token aud does not contain expected audience: " + expectedAudience);
        }
    }

    private void verifyNonce(Map<String, Object> claims, String expectedNonce) {
        if (expectedNonce == null) {
            return;
        }
        Object nonce = claims.get("nonce");
        if (nonce == null || !expectedNonce.equals(nonce.toString())) {
            throw new IllegalArgumentException("ID token nonce does not match expected nonce");
        }
    }

    private void verifyTimeValidity(Map<String, Object> claims) {
        Instant now = Instant.now();
        Instant exp = instantClaim(claims, "exp");
        if (exp != null && now.isAfter(exp.plusSeconds(clockSkewSeconds))) {
            throw new IllegalArgumentException("ID token is expired");
        }
        Instant iat = instantClaim(claims, "iat");
        if (iat != null && now.isBefore(iat.minusSeconds(clockSkewSeconds))) {
            throw new IllegalArgumentException("ID token issued in the future");
        }
    }

    private String stringClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        return value != null ? value.toString() : null;
    }

    private Instant instantClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        if (value != null) {
            return Instant.ofEpochSecond(Long.parseLong(value.toString()));
        }
        return null;
    }

    private List<String> audience(Map<String, Object> claims) {
        Object aud = claims.get("aud");
        if (aud instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return aud != null ? List.of(aud.toString()) : List.of();
    }
}
