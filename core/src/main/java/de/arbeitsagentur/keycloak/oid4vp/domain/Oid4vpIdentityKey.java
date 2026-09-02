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
import java.util.Locale;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

/**
 * The brokered identity of an OID4VP login, derived from the subject alone. Keycloak already
 * scopes the key to the identity provider alias, and leaving issuer and credential format out of
 * it means a user presenting the same subject in different credential formats reaches the same
 * Keycloak identity.
 */
public final class Oid4vpIdentityKey {

    private Oid4vpIdentityKey() {}

    public static String of(String subject) {
        return hash(normalize(subject));
    }

    /**
     * Returns the identity key of a subject, ignoring case, because human readable credential
     * claims vary in casing across formats and still mean the same user.
     */
    public static String caseInsensitive(String subject) {
        return hash(normalize(subject).toLowerCase(Locale.ROOT));
    }

    private static String hash(String normalizedSubject) {
        return Base64Url.encode(
                HashUtils.hash(JavaAlgorithm.SHA256, normalizedSubject.getBytes(StandardCharsets.UTF_8)));
    }

    private static String normalize(String value) {
        return value != null ? value.strip() : "";
    }
}
