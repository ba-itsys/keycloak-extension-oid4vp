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
 * The identifier of a credential entry in a DCQL query. The id names the credential in the
 * {@code credential_sets} constraints and is the key under which the wallet returns the matching
 * presentation in the {@code vp_token}, so it must stay stable across mapper changes.
 *
 * <p>A mapper may configure the id explicitly; otherwise it is derived from the credential format
 * and type. DCQL restricts the id to non-empty strings of alphanumeric, underscore and hyphen
 * characters, so every other character of a derived id is replaced by an underscore.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OID4VP 1.0 §6.1 — Credential Query</a>
 */
public final class CredentialId {

    private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern ILLEGAL_CHARACTERS = Pattern.compile("[^A-Za-z0-9_-]");

    private static final String SD_JWT_PREFIX = "sdjwt";
    private static final String MDOC_PREFIX = "mdoc";

    private CredentialId() {}

    /** The id used when a mapper does not configure one: the format prefix and the slugged type. */
    public static String defaultFor(String format, String type) {
        return formatPrefix(format) + "_" + slug(type);
    }

    /**
     * The credential id a mapper contributes to: its configured id when that is a valid DCQL id, and the
     * id derived from format and type otherwise. Request-side DCQL generation and response-side mapping
     * must resolve the id the same way, so that a mapper configured with an invalid id maps against the
     * same credential the wallet was asked to present rather than silently mapping nothing.
     */
    public static String resolve(String configuredId, String format, String type) {
        String trimmed = configuredId == null ? null : configuredId.trim();
        if (trimmed != null && !trimmed.isEmpty() && isValid(trimmed)) {
            return trimmed;
        }
        return defaultFor(format, type);
    }

    public static boolean isValid(String credentialId) {
        return credentialId != null && VALID_ID.matcher(credentialId).matches();
    }

    private static String formatPrefix(String format) {
        if (Oid4vpConstants.FORMAT_SD_JWT_VC.equals(format)) {
            return SD_JWT_PREFIX;
        }
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equals(format)) {
            return MDOC_PREFIX;
        }
        return slug(format);
    }

    private static String slug(String value) {
        return value == null ? "" : ILLEGAL_CHARACTERS.matcher(value).replaceAll("_");
    }
}
