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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class WalletMetadataTest {

    @Test
    void parse_validMetadata_extractsKeyAndAlgorithms() {
        Oid4vpJwk generated = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        Oid4vpJwk walletKey = new Oid4vpJwk(
                generated.curve(), generated.x(), generated.y(), null, "wallet-enc-key", "ECDH-ES", "enc");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.encryptionKey().keyId()).isEqualTo("wallet-enc-key");
        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
        assertThat(result.encryptionMethod()).isEqualTo("A128GCM");
    }

    @Test
    void parse_a256gcm_selectsA256gcm() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A256GCM");

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.encryptionMethod()).isEqualTo("A256GCM");
    }

    @Test
    void parse_noAlgOrEncSpecified_defaultsToEcdhEsA128gcm() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = """
                {"jwks":{"keys":[%s]}}""".formatted(walletKey.toPublicJwk().toJson());

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
        assertThat(result.encryptionMethod()).isEqualTo("A128GCM");
    }

    @Test
    void parse_unsupportedAlgorithm_throws() {
        Oid4vpJwk walletKey = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "RSA-OAEP-256", "A128GCM");

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No supported algorithm");
    }

    @Test
    void parse_unsupportedEncryptionMethod_throws() {
        Oid4vpJwk walletKey = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A192GCM");

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No supported encryption method");
    }

    @Test
    void parse_missingJwks_throws() {
        String json = """
                {"authorization_encryption_alg_values_supported":["ECDH-ES"]}""";

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("missing 'jwks'");
    }

    @Test
    void parse_invalidJson_throws() {
        assertThatThrownBy(() -> WalletMetadata.parse("not json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid wallet_metadata JSON");
    }

    @Test
    void parse_emptyJwks_throws() {
        String json = """
                {"jwks":{"keys":[]}}""";

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No EC key found");
    }

    private static String buildWalletMetadataJson(Oid4vpJwk publicKey, String alg, String enc) {
        return """
                {
                  "authorization_encryption_alg_values_supported":["%s"],
                  "authorization_encryption_enc_values_supported":["%s"],
                  "jwks":{"keys":[%s]}
                }""".formatted(alg, enc, publicKey.toJson());
    }

    private static Oid4vpJwk withKid(Oid4vpJwk jwk, String kid) {
        return new Oid4vpJwk(jwk.curve(), jwk.x(), jwk.y(), jwk.privateKey(), kid, jwk.algorithm(), jwk.use());
    }
}
