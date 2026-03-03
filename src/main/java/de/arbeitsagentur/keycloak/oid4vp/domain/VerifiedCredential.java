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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

/**
 * A credential that has been cryptographically verified and had its claims extracted.
 *
 * <p>Produced by {@link de.arbeitsagentur.keycloak.oid4vp.verification.SdJwtVerifier} or
 * {@link de.arbeitsagentur.keycloak.oid4vp.verification.MdocVerifier} after validating
 * the issuer signature, key binding, and revocation status.
 */
public record VerifiedCredential(
        String credentialId,
        String issuer,
        String credentialType,
        Map<String, Object> claims,
        PresentationType presentationType) {

    /**
     * Generates a stable identity key from the subject claim only.
     * The key is scoped to the IdP alias by Keycloak, so issuer is not included —
     * this allows the same user to authenticate with different credential formats
     * (SD-JWT / mDoc) and still be matched to the same Keycloak identity.
     */
    public String generateIdentityKey(String subject) {
        String normalizedSubject = normalize(subject);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalizedSubject.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String normalize(String value) {
        return value != null ? value.strip().toLowerCase(Locale.ROOT) : "";
    }
}
