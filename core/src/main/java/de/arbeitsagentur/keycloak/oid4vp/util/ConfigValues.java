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
package de.arbeitsagentur.keycloak.oid4vp.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Normalizes multi-line configuration values that reach the identity provider config through
 * single-line transports such as environment variables.
 *
 * <p>A value is used verbatim unless it is Base64-encoded as a whole, recognized by the decoded
 * text carrying the expected content marker: a PEM {@code -----BEGIN} header, or a leading
 * <code>'&#123;'</code> or {@code '['} for JSON. PEM values additionally accept {@code \n} escape sequences
 * instead of newlines.
 */
public final class ConfigValues {

    private static final String PEM_MARKER = "-----BEGIN";

    private ConfigValues() {}

    /** Returns the configured PEM bundle as multi-line PEM. */
    public static String pem(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String effective = value;
        if (!value.contains(PEM_MARKER)) {
            String decoded = decodeBase64(value);
            if (decoded != null && decoded.contains(PEM_MARKER)) {
                effective = decoded;
            }
        }
        return effective.replace("\\n", "\n");
    }

    /** Returns the configured JSON value. */
    public static String json(String value) {
        if (value == null || value.isBlank() || startsJson(value)) {
            return value;
        }
        String decoded = decodeBase64(value);
        return decoded != null && startsJson(decoded) ? decoded : value;
    }

    private static boolean startsJson(String value) {
        String trimmed = value.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    /**
     * Decodes with the MIME decoder so values wrapped by {@code base64(1)} are read as well.
     * Returns {@code null} when the value is not Base64.
     */
    private static String decodeBase64(String value) {
        try {
            return new String(Base64.getMimeDecoder().decode(value.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
