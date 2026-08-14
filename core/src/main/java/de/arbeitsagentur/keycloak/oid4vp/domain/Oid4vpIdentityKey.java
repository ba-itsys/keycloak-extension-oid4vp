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
 * The brokered identity of an OID4VP login, derived from the subject alone.
 *
 * <p>The key is scoped to the identity provider alias by Keycloak, so neither the issuer nor the
 * credential format is part of it. A user presenting the same subject in different credential
 * formats therefore reaches the same Keycloak identity.
 *
 * <p>Both sides of a login that establishes a subject use this, so a login that only learns the
 * subject later derives the same key as the presentation that carries it.
 */
public final class Oid4vpIdentityKey {

    private Oid4vpIdentityKey() {}

    /** The identity key of a subject, matching it exactly. */
    public static String of(String subject) {
        return hash(normalize(subject));
    }

    /**
     * The identity key of a subject, matching it without regard to case. Human readable credential
     * claims vary in casing across formats while meaning the same user.
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
