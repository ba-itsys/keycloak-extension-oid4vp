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
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * A credential whose issuer signature, key binding and revocation status are checked and whose
 * claims are extracted. {@code alsoKnownAsTypes} are the further types an SD-JWT VC names in its
 * {@code aka_vcts} claim, which an mDoc has none of.
 */
public record VerifiedCredential(
        String credentialId,
        String issuer,
        String credentialType,
        Map<String, Object> claims,
        PresentationType presentationType,
        List<String> alsoKnownAsTypes) {

    public VerifiedCredential {
        alsoKnownAsTypes = alsoKnownAsTypes != null ? List.copyOf(alsoKnownAsTypes) : List.of();
    }

    public VerifiedCredential(
            String credentialId,
            String issuer,
            String credentialType,
            Map<String, Object> claims,
            PresentationType presentationType) {
        this(credentialId, issuer, credentialType, claims, presentationType, List.of());
    }

    public boolean isOfType(String requestedType) {
        return CredentialTypeHierarchy.isOfType(credentialType, alsoKnownAsTypes, requestedType);
    }

    public String generateIdentityKey(String subject) {
        return Oid4vpIdentityKey.of(subject);
    }

    public String generateCaseInsensitiveIdentityKey(String subject) {
        return Oid4vpIdentityKey.caseInsensitive(subject);
    }

    public JsonNode claimsNode() {
        return JsonSerialization.mapper.valueToTree(claims);
    }
}
