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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.utils.StringUtil;

public enum Oid4vpTrustedAuthoritiesMode {
    NONE("none"),
    ETSI_TL(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_ETSI_TL),
    AKI(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_AKI);

    private final String configValue;

    Oid4vpTrustedAuthoritiesMode(String configValue) {
        this.configValue = configValue;
    }

    public String configValue() {
        return configValue;
    }

    public boolean isEnabled() {
        return this != NONE;
    }

    public List<Map<String, Object>> toDcqlEntries(String trustListUrl, List<String> authorityKeyIdentifiers) {
        return switch (this) {
            case NONE -> List.of();
            case ETSI_TL ->
                StringUtil.isBlank(trustListUrl)
                        ? List.of()
                        : List.of(toDcqlEntry(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_ETSI_TL, List.of(trustListUrl)));
            case AKI ->
                authorityKeyIdentifiers == null || authorityKeyIdentifiers.isEmpty()
                        ? List.of()
                        : List.of(toDcqlEntry(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_AKI, authorityKeyIdentifiers));
        };
    }

    public static Oid4vpTrustedAuthoritiesMode resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return NONE;
        }
        for (Oid4vpTrustedAuthoritiesMode mode : values()) {
            if (mode.configValue.equalsIgnoreCase(rawValue)) {
                return mode;
            }
        }
        return NONE;
    }

    private static Map<String, Object> toDcqlEntry(String type, List<String> values) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_TYPE, type);
        entry.put(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_VALUES, values);
        return entry;
    }
}
