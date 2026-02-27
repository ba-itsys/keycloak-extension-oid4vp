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
package de.arbeitsagentur.keycloak.oid4vp;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;

class FederatedIdentityKeyGeneratorTest {

    @Test
    void generate_sameInputs_sameHash() {
        String key1 = FederatedIdentityKeyGenerator.generate("issuer1", "IdentityCredential", "user123");
        String key2 = FederatedIdentityKeyGenerator.generate("issuer1", "IdentityCredential", "user123");

        assertThat(key1).isEqualTo(key2);
    }

    @Test
    void generate_differentIssuers_differentHashes() {
        String key1 = FederatedIdentityKeyGenerator.generate("issuer1", "IdentityCredential", "user123");
        String key2 = FederatedIdentityKeyGenerator.generate("issuer2", "IdentityCredential", "user123");

        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    void generate_differentSubjects_differentHashes() {
        String key1 = FederatedIdentityKeyGenerator.generate("issuer1", "IdentityCredential", "user1");
        String key2 = FederatedIdentityKeyGenerator.generate("issuer1", "IdentityCredential", "user2");

        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    void generate_differentCredentialTypes_differentHashes() {
        String key1 = FederatedIdentityKeyGenerator.generate("issuer1", "Type1", "user123");
        String key2 = FederatedIdentityKeyGenerator.generate("issuer1", "Type2", "user123");

        assertThat(key1).isNotEqualTo(key2);
    }

    @Test
    void generate_nullValues_doesNotThrow() {
        String key = FederatedIdentityKeyGenerator.generate(null, null, null);
        assertThat(key).isNotNull().isNotEmpty();
    }

    @Test
    void generate_nullIssuerDifferentFromEmpty() {
        String keyNull = FederatedIdentityKeyGenerator.generate(null, "Type", "user");
        String keyEmpty = FederatedIdentityKeyGenerator.generate("", "Type", "user");

        assertThat(keyNull).isEqualTo(keyEmpty);
    }

    @Test
    void generate_returnsBase64UrlEncoded() {
        String key = FederatedIdentityKeyGenerator.generate("issuer", "type", "subject");
        // SHA-256 produces 32 bytes → 43 base64url chars (without padding)
        assertThat(key).hasSize(43);
        assertThat(key).matches("[A-Za-z0-9_-]+");
    }
}
