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
    void encryptionRequestedBy_validMetadata_extractsKeyAndAlgorithms() {
        Oid4vpJwk generated = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        Oid4vpJwk walletKey = new Oid4vpJwk(
                generated.curve(), generated.x(), generated.y(), null, "wallet-enc-key", "ECDH-ES", "enc");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.encryptionKey().keyId()).isEqualTo("wallet-enc-key");
        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
        assertThat(result.encryptionMethod()).isEqualTo("A128GCM");
    }

    @Test
    void encryptionRequestedBy_a256gcm_selectsA256gcm() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A256GCM");

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.encryptionMethod()).isEqualTo("A256GCM");
    }

    @Test
    void encryptionRequestedBy_noAlgOrEncSpecified_defaultsToEcdhEsA128gcm() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = """
                {"jwks":{"keys":[%s]}}""".formatted(walletKey.toPublicJwk().toJson());

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
        assertThat(result.encryptionMethod()).isEqualTo("A128GCM");
    }

    @Test
    void encryptionRequestedBy_unsupportedAdvertisedAlgorithm_usesTheAlgorithmOfTheKey() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "RSA-OAEP-256", "A128GCM");

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
    }

    @Test
    void encryptionRequestedBy_unsupportedEncryptionMethod_fallsBackToA128gcm() {
        Oid4vpJwk walletKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "k1");
        String json = buildWalletMetadataJson(walletKey.toPublicJwk(), "ECDH-ES", "A192GCM");

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.encryptionMethod()).isEqualTo("A128GCM");
    }

    @Test
    void encryptionRequestedBy_signingKeyListedFirst_selectsTheEncryptionKey() {
        Oid4vpJwk signingKey = withKid(Oid4vpJwk.generate("P-256", "ES256", "sig"), "wallet-sig-key");
        Oid4vpJwk encryptionKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "wallet-enc-key");
        String json = """
                {"jwks":{"keys":[%s,%s]}}""".formatted(
                signingKey.toPublicJwk().toJson(), encryptionKey.toPublicJwk().toJson());

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.encryptionKey().keyId()).isEqualTo("wallet-enc-key");
        assertThat(result.algorithm()).isEqualTo("ECDH-ES");
    }

    @Test
    void encryptionRequestedBy_nonEcKeyListedFirst_selectsTheEncryptionKey() {
        Oid4vpJwk encryptionKey = withKid(Oid4vpJwk.generate("P-256", "ECDH-ES", "enc"), "wallet-enc-key");
        String json = """
                {"jwks":{"keys":[{"kty":"RSA","kid":"rsa-key","use":"enc","alg":"RSA-OAEP-256","n":"sXchDaQ","e":"AQAB"},%s]}}""".formatted(encryptionKey.toPublicJwk().toJson());

        WalletMetadata result = WalletMetadata.encryptionRequestedBy(json).orElseThrow();

        assertThat(result.encryptionKey().keyId()).isEqualTo("wallet-enc-key");
    }

    @Test
    void encryptionRequestedBy_onlyKeysForOtherPurposes_requestsNoEncryption() {
        Oid4vpJwk signingKey = withKid(Oid4vpJwk.generate("P-256", "ES256", "sig"), "wallet-sig-key");
        String json = """
                {"jwks":{"keys":[%s]}}""".formatted(signingKey.toPublicJwk().toJson());

        assertThat(WalletMetadata.encryptionRequestedBy(json)).isEmpty();
    }

    @Test
    void encryptionRequestedBy_metadataWithoutJwks_requestsNoEncryption() {
        String json = """
                {"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}}}""";

        assertThat(WalletMetadata.encryptionRequestedBy(json)).isEmpty();
    }

    @Test
    void encryptionRequestedBy_invalidJson_throws() {
        assertThatThrownBy(() -> WalletMetadata.encryptionRequestedBy("not json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid wallet_metadata JSON");
    }

    @Test
    void encryptionRequestedBy_emptyJwks_requestsNoEncryption() {
        String json = """
                {"jwks":{"keys":[]}}""";

        assertThat(WalletMetadata.encryptionRequestedBy(json)).isEmpty();
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
