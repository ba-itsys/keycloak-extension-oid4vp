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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

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

    /** The identity key of the subject claim, see {@link Oid4vpIdentityKey#of}. */
    public String generateIdentityKey(String subject) {
        return Oid4vpIdentityKey.of(subject);
    }

    /** The case-insensitive identity key of the subject, see {@link Oid4vpIdentityKey#caseInsensitive}. */
    public String generateCaseInsensitiveIdentityKey(String subject) {
        return Oid4vpIdentityKey.caseInsensitive(subject);
    }

    /** The claims as a JSON tree, which is what a {@code ClaimPath} resolves against. */
    public JsonNode claimsNode() {
        return JsonSerialization.mapper.valueToTree(claims);
    }
}
