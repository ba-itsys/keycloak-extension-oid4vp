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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;

public class SdJwtVerifier {

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);
    private static final long CLOCK_SKEW_SECONDS = 60;
    private static final Duration KB_JWT_MAX_AGE = Duration.ofMinutes(5);

    private final ObjectMapper objectMapper;

    public SdJwtVerifier(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    public VerificationResult verify(
            String sdJwt,
            String expectedAudience,
            String expectedNonce,
            boolean trustX5cFromCredential,
            boolean skipSignatureVerification) {

        SdJwtParts parts = split(sdJwt);

        try {
            SignedJWT jwt = SignedJWT.parse(parts.signedJwt());

            if (!skipSignatureVerification) {
                verifySignature(jwt, trustX5cFromCredential);
            }

            validateTimestamps(jwt);

            Map<String, Object> claims = extractDisclosedClaims(jwt, parts);

            if (parts.keyBindingJwt() != null && !parts.keyBindingJwt().isBlank()) {
                verifyKeyBinding(parts, jwt, expectedAudience, expectedNonce);
            }

            String issuer = claims.containsKey("iss") ? claims.get("iss").toString() : null;
            String vct = claims.containsKey("vct") ? claims.get("vct").toString() : null;

            return new VerificationResult(claims, issuer, vct);
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    private void verifySignature(SignedJWT jwt, boolean trustX5cFromCredential) throws Exception {
        if (trustX5cFromCredential) {
            List<com.nimbusds.jose.util.Base64> x5c = jwt.getHeader().getX509CertChain();
            if (x5c != null && !x5c.isEmpty()) {
                byte[] certBytes = x5c.get(0).decode();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                PublicKey publicKey = cert.getPublicKey();
                verifyWithPublicKey(jwt, publicKey);
                return;
            }
        }

        // Try JWK from header
        com.nimbusds.jose.jwk.JWK jwk = jwt.getHeader().getJWK();
        if (jwk != null) {
            verifyWithPublicKey(jwt, jwk.toPublicJWK().toECKey().toPublicKey());
            return;
        }

        LOG.warnf("No key found for signature verification, skipping");
    }

    private void verifyWithPublicKey(SignedJWT jwt, PublicKey publicKey) throws Exception {
        JWSVerifier verifier;
        if (publicKey instanceof ECPublicKey ecKey) {
            verifier = new ECDSAVerifier(ecKey);
        } else if (publicKey instanceof RSAPublicKey rsaKey) {
            verifier = new RSASSAVerifier(rsaKey);
        } else {
            throw new IllegalStateException("Unsupported key type: " + publicKey.getAlgorithm());
        }

        if (!jwt.verify(verifier)) {
            throw new IllegalStateException("SD-JWT signature verification failed");
        }
    }

    private void validateTimestamps(SignedJWT jwt) throws Exception {
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        Instant now = Instant.now();

        Date exp = claims.getExpirationTime();
        if (exp != null && exp.toInstant().plusSeconds(CLOCK_SKEW_SECONDS).isBefore(now)) {
            throw new IllegalStateException("SD-JWT has expired");
        }

        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.toInstant().minusSeconds(CLOCK_SKEW_SECONDS).isAfter(now)) {
            throw new IllegalStateException("SD-JWT not yet valid");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractDisclosedClaims(SignedJWT jwt, SdJwtParts parts) throws Exception {
        Map<String, Object> payload = objectMapper.readValue(jwt.getPayload().toBytes(), Map.class);

        Map<String, Object> claims = new LinkedHashMap<>(payload);

        // Process disclosures
        String hashAlg = payload.containsKey("_sd_alg") ? payload.get("_sd_alg").toString() : "sha-256";

        for (String disclosure : parts.disclosures()) {
            if (disclosure == null || disclosure.isBlank()) continue;
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(disclosure);
                List<Object> disclosureArray = objectMapper.readValue(decoded, List.class);
                if (disclosureArray.size() >= 3) {
                    String claimName = disclosureArray.get(1).toString();
                    Object claimValue = disclosureArray.get(2);
                    claims.put(claimName, claimValue);
                }
            } catch (Exception e) {
                LOG.debugf("Failed to decode disclosure: %s", e.getMessage());
            }
        }

        // Remove SD-JWT internal claims
        claims.remove("_sd");
        claims.remove("_sd_alg");
        claims.remove("..."); // decoy digests

        return claims;
    }

    private void verifyKeyBinding(
            SdJwtParts parts, SignedJWT credentialJwt, String expectedAudience, String expectedNonce) throws Exception {
        SignedJWT kbJwt = SignedJWT.parse(parts.keyBindingJwt());

        // Verify KB-JWT signature with credential's cnf key
        JWTClaimsSet credClaims = credentialJwt.getJWTClaimsSet();
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) credClaims.getClaim("cnf");
        if (cnf != null && cnf.containsKey("jwk")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
            String jwkJson = objectMapper.writeValueAsString(jwkMap);
            com.nimbusds.jose.jwk.JWK holderKey = com.nimbusds.jose.jwk.JWK.parse(jwkJson);
            PublicKey holderPublicKey;
            if (holderKey instanceof ECKey ecKey) {
                holderPublicKey = ecKey.toPublicKey();
            } else if (holderKey instanceof RSAKey rsaKey) {
                holderPublicKey = rsaKey.toPublicKey();
            } else {
                throw new IllegalStateException("Unsupported holder key type");
            }
            verifyWithPublicKey(kbJwt, holderPublicKey);
        }

        JWTClaimsSet kbClaims = kbJwt.getJWTClaimsSet();

        // Validate timestamps
        Date iat = kbClaims.getIssueTime();
        if (iat != null) {
            Duration age = Duration.between(iat.toInstant(), Instant.now());
            if (age.abs().compareTo(KB_JWT_MAX_AGE) > 0) {
                throw new IllegalStateException("KB-JWT is too old");
            }
        }

        // Validate audience
        if (expectedAudience != null) {
            String kbAud =
                    kbClaims.getAudience() != null && !kbClaims.getAudience().isEmpty()
                            ? kbClaims.getAudience().get(0)
                            : null;
            if (kbAud != null && !kbAud.equals(expectedAudience)) {
                LOG.warnf("KB-JWT audience mismatch: expected=%s, got=%s", expectedAudience, kbAud);
            }
        }

        // Validate nonce
        if (expectedNonce != null) {
            String kbNonce = kbClaims.getStringClaim("nonce");
            if (kbNonce != null && !kbNonce.equals(expectedNonce)) {
                LOG.warnf("KB-JWT nonce mismatch: expected=%s, got=%s", expectedNonce, kbNonce);
            }
        }

        // Validate sd_hash
        String sdHash = kbClaims.getStringClaim("sd_hash");
        if (sdHash != null) {
            String presentationWithoutKb = parts.signedJwt();
            for (String disc : parts.disclosures()) {
                if (disc != null && !disc.isBlank()) {
                    presentationWithoutKb += "~" + disc;
                }
            }
            presentationWithoutKb += "~";

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(presentationWithoutKb.getBytes(StandardCharsets.US_ASCII));
            String computedHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            if (!computedHash.equals(sdHash)) {
                throw new IllegalStateException("KB-JWT sd_hash mismatch");
            }
        }
    }

    static SdJwtParts split(String sdJwt) {
        String[] segments = sdJwt.split("~", -1);
        String signedJwt = segments[0];
        List<String> disclosures = new ArrayList<>();
        String keyBindingJwt = null;

        for (int i = 1; i < segments.length; i++) {
            if (i == segments.length - 1) {
                // Last segment: if non-empty it's the KB-JWT, if empty it's just the trailing ~
                if (!segments[i].isBlank()) {
                    keyBindingJwt = segments[i];
                }
            } else {
                if (!segments[i].isBlank()) {
                    disclosures.add(segments[i]);
                }
            }
        }

        return new SdJwtParts(signedJwt, disclosures, keyBindingJwt);
    }

    public record SdJwtParts(String signedJwt, List<String> disclosures, String keyBindingJwt) {}

    public record VerificationResult(Map<String, Object> claims, String issuer, String credentialType) {}
}
