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

import java.util.regex.Pattern;

/**
 * The character set DCQL allows for its identifiers. Credential ids and claim ids are both
 * restricted to non-empty strings of alphanumeric, underscore and hyphen characters, so a value
 * taken from configuration is slugged before it names an entry of the query.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OID4VP 1.0 §6.1 — Credential Query</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public final class DcqlId {

    private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern ILLEGAL_CHARACTERS = Pattern.compile("[^A-Za-z0-9_-]");

    private DcqlId() {}

    public static boolean isValid(String id) {
        return id != null && VALID_ID.matcher(id).matches();
    }

    /** Replaces every character DCQL does not allow in an id by an underscore; null reads as empty. */
    public static String slug(String value) {
        return value == null ? "" : ILLEGAL_CHARACTERS.matcher(value).replaceAll("_");
    }
}
