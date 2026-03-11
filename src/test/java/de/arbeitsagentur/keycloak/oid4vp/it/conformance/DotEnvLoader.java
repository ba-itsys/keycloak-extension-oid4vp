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
package de.arbeitsagentur.keycloak.oid4vp.it.conformance;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

final class DotEnvLoader {

    private DotEnvLoader() {}

    static Map<String, String> loadFromWorkingDirectory() {
        Path dir = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath();
        for (int i = 0; i < 6 && dir != null; i++) {
            Path candidate = dir.resolve(".env");
            if (Files.isRegularFile(candidate)) {
                return parse(candidate);
            }
            dir = dir.getParent();
        }
        return Map.of();
    }

    static Map<String, String> parse(Path file) {
        Map<String, String> values = new LinkedHashMap<>();
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                int separator = trimmed.indexOf('=');
                if (separator <= 0) {
                    continue;
                }
                String key = trimmed.substring(0, separator).trim();
                String value = trimmed.substring(separator + 1).trim();
                values.put(key, stripOptionalQuotes(value));
            }
        } catch (IOException e) {
            return Map.of();
        }
        return values;
    }

    private static String stripOptionalQuotes(String value) {
        if (value.length() >= 2) {
            if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }
}
