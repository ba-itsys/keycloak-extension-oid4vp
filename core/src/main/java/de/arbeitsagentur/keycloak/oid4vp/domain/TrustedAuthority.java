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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One DCQL {@code trusted_authorities} entry, naming an authority type and the values the verifier
 * accepts for it. The query carries the entries of the trust material providers serving a
 * credential.
 *
 * <p>A credential matches when it matches one value of one entry, so several entries of different
 * types are alternatives and not a conjunction.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1 — Trusted Authorities Query</a>
 */
public record TrustedAuthority(TrustedAuthorityType type, List<String> values) {

    public TrustedAuthority {
        values = values != null ? List.copyOf(values) : List.of();
    }

    public static List<TrustedAuthority> of(TrustedAuthorityType type, List<String> values) {
        return values == null || values.isEmpty() ? List.of() : List.of(new TrustedAuthority(type, values));
    }

    /**
     * Merges the entries of several providers into one entry per type. Types and values keep the
     * order of their first occurrence.
     */
    public static List<TrustedAuthority> merge(List<TrustedAuthority> entries) {
        Map<TrustedAuthorityType, Set<String>> valuesByType = new LinkedHashMap<>();
        for (TrustedAuthority entry : entries) {
            if (entry == null || entry.values().isEmpty()) {
                continue;
            }
            valuesByType
                    .computeIfAbsent(entry.type(), type -> new LinkedHashSet<>())
                    .addAll(entry.values());
        }
        List<TrustedAuthority> merged = new ArrayList<>();
        valuesByType.forEach((type, values) -> merged.add(new TrustedAuthority(type, List.copyOf(values))));
        return List.copyOf(merged);
    }

    public Map<String, Object> toDcqlEntry() {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_TYPE, type.dcqlValue());
        entry.put(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_VALUES, values);
        return entry;
    }

    public static List<Map<String, Object>> toDcqlEntries(List<TrustedAuthority> entries) {
        return entries.stream()
                .filter(entry -> !entry.values().isEmpty())
                .map(TrustedAuthority::toDcqlEntry)
                .toList();
    }
}
