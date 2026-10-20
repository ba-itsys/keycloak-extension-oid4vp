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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class Oid4vpRequestObjectStoreTest {

    @Test
    void statesWithinTheMaximumAreKept() {
        assertThat(Oid4vpRequestObjectStore.evictedStates(List.of("a", "b"), 2)).isEmpty();
    }

    @Test
    void oldestStatesBeyondTheMaximumAreEvicted() {
        assertThat(Oid4vpRequestObjectStore.evictedStates(List.of("a", "b", "c", "d", "e"), 3))
                .containsExactly("a", "b");
    }
}
