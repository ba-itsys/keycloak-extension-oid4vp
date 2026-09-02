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

/**
 * The identifier of a credential entry in a DCQL query. It names the credential in the
 * {@code credential_sets} constraints and is the key under which the wallet returns the matching
 * presentation in the {@code vp_token}, so it has to stay stable across mapper changes.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">OID4VP 1.0 §6.1 — Credential Query</a>
 */
public final class CredentialId {

    private static final String SD_JWT_PREFIX = "sdjwt";
    private static final String MDOC_PREFIX = "mdoc";

    private CredentialId() {}

    public static String defaultFor(String format, String type) {
        return formatPrefix(format) + "_" + DcqlId.slug(type);
    }

    /**
     * Resolves the credential id a mapper contributes to, falling back to the derived id when the
     * configured one is not a valid DCQL id. Query generation and response mapping have to resolve
     * the id the same way, so a mapper with an invalid id still maps against the credential the
     * wallet was asked to present instead of silently mapping nothing.
     */
    public static String resolve(String configuredId, String format, String type) {
        String trimmed = configuredId == null ? null : configuredId.trim();
        if (trimmed != null && !trimmed.isEmpty() && isValid(trimmed)) {
            return trimmed;
        }
        return defaultFor(format, type);
    }

    public static boolean isValid(String credentialId) {
        return DcqlId.isValid(credentialId);
    }

    private static String formatPrefix(String format) {
        if (Oid4vpConstants.FORMAT_SD_JWT_VC.equals(format)) {
            return SD_JWT_PREFIX;
        }
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equals(format)) {
            return MDOC_PREFIX;
        }
        return DcqlId.slug(format);
    }
}
