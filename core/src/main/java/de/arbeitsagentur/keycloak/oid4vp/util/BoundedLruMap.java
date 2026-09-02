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
 * Bounds the caches of this extension, which are keyed by values that credentials and configuration
 * bring with them. Since the verifier does not control that key space, an unbounded map would grow
 * with whatever a wallet presents.
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
