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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A map with an upper bound on its size that drops the entry least recently used once the bound is
 * reached. The caches of this extension are keyed by values credentials and configuration bring
 * with them, so their key space is not the verifier's to choose and needs a bound.
 */
public final class BoundedLruMap {

    private BoundedLruMap() {}

    public static <K, V> Map<K, V> withMaxEntries(int maxEntries) {
        return Collections.synchronizedMap(new LinkedHashMap<K, V>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        });
    }
}
