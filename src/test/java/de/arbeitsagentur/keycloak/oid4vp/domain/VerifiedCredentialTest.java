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

import java.util.Map;
import org.junit.jupiter.api.Test;

class VerifiedCredentialTest {

    private final VerifiedCredential credential = new VerifiedCredential(
            "cred1", "https://issuer.example", "IdentityCredential", Map.of("sub", "Example"), PresentationType.SD_JWT);

    @Test
    void generateIdentityKey_preservesCaseForCryptographicSubjects() {
        String upper = credential.generateIdentityKey("AbCdEf123");
        String lower = credential.generateIdentityKey("abcdef123");

        assertThat(upper).isNotEqualTo(lower);
    }

    @Test
    void generateCaseInsensitiveIdentityKey_matchesSubjectsThatOnlyDifferByCase() {
        String upper = credential.generateCaseInsensitiveIdentityKey("ExampleUser");
        String lower = credential.generateCaseInsensitiveIdentityKey("exampleuser");

        assertThat(upper).isEqualTo(lower);
    }
}
