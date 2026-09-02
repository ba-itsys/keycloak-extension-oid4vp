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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class Oid4vpIdentityKeyTest {

    @Test
    void theSameSubjectAlwaysReachesTheSameIdentity() {
        assertThat(Oid4vpIdentityKey.of("user-1")).isEqualTo(Oid4vpIdentityKey.of("  user-1  "));
        assertThat(Oid4vpIdentityKey.of("user-1")).isNotEqualTo(Oid4vpIdentityKey.of("user-2"));
    }

    @Test
    void casingSeparatesIdentitiesOnlyWhenItIsMeantTo() {
        assertThat(Oid4vpIdentityKey.of("User-1")).isNotEqualTo(Oid4vpIdentityKey.of("user-1"));
        assertThat(Oid4vpIdentityKey.caseInsensitive("User-1")).isEqualTo(Oid4vpIdentityKey.caseInsensitive("user-1"));
    }

    @Test
    void everySubjectlessLoginWouldReachTheSameIdentity() {
        // The verifier rejects a presentation without a principal claim, and generates a subject
        // when the claim may be missing. Deriving a key from a blank subject here instead would put
        // every such login on one shared account.
        assertThat(Oid4vpIdentityKey.of(null)).isEqualTo(Oid4vpIdentityKey.of(""));
        assertThat(Oid4vpIdentityKey.of("   ")).isEqualTo(Oid4vpIdentityKey.of(""));
        assertThat(Oid4vpIdentityKey.of(null))
                .as("a blank subject is still not the literal string a wallet could send")
                .isNotEqualTo(Oid4vpIdentityKey.of("null"));
    }
}
