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
 * single-line transports such as environment variables. A value is used verbatim unless decoding it
 * as Base64 yields text carrying the expected content marker, which is how a wrapped value is told
 * apart from a literal one.
 */
public final class ConfigValues {

    private static final String PEM_MARKER = "-----BEGIN";

    private ConfigValues() {}

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

    /** Decodes with the MIME decoder so that values line-wrapped by {@code base64(1)} are read as well. */
    private static String decodeBase64(String value) {
        try {
            return new String(Base64.getMimeDecoder().decode(value.trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
