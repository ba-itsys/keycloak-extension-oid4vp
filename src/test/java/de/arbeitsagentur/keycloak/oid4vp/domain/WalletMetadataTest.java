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

import static org.assertj.core.api.Assertions.*;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

class WalletMetadataTest {

    @Test
    void parse_validMetadata_extractsKeyAndAlgorithms() throws Exception {
        ECKey walletKey =
                new ECKeyGenerator(Curve.P_256).keyID("wallet-enc-key").generate();
        String json = buildWalletMetadataJson(walletKey.toPublicJWK(), "ECDH-ES", "A128GCM");

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.encryptionKey().getKeyID()).isEqualTo("wallet-enc-key");
        assertThat(result.algorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(result.encryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
    }

    @Test
    void parse_a256gcm_selectsA256gcm() throws Exception {
        ECKey walletKey = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        String json = buildWalletMetadataJson(walletKey.toPublicJWK(), "ECDH-ES", "A256GCM");

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.encryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
    }

    @Test
    void parse_noAlgOrEncSpecified_defaultsToEcdhEsA128gcm() throws Exception {
        ECKey walletKey = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        String json = """
                {"jwks":{"keys":[%s]}}""".formatted(walletKey.toPublicJWK().toJSONString());

        WalletMetadata result = WalletMetadata.parse(json);

        assertThat(result.algorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(result.encryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
    }

    @Test
    void parse_unsupportedAlgorithm_throws() throws Exception {
        ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
        String json = buildWalletMetadataJson(walletKey.toPublicJWK(), "RSA-OAEP-256", "A128GCM");

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No supported algorithm");
    }

    @Test
    void parse_unsupportedEncryptionMethod_throws() throws Exception {
        ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
        String json = buildWalletMetadataJson(walletKey.toPublicJWK(), "ECDH-ES", "A192GCM");

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
    void parse_emptyJwks_throws() throws Exception {
        String json = """
                {"jwks":{"keys":[]}}""";

        assertThatThrownBy(() -> WalletMetadata.parse(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No EC key found");
    }

    private static String buildWalletMetadataJson(ECKey publicKey, String alg, String enc) {
        return """
                {
                  "authorization_encryption_alg_values_supported":["%s"],
                  "authorization_encryption_enc_values_supported":["%s"],
                  "jwks":{"keys":[%s]}
                }""".formatted(alg, enc, publicKey.toJSONString());
    }
}
