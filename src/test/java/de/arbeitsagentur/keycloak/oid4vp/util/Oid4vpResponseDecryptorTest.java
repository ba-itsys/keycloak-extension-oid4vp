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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.util.JsonSerialization;

class Oid4vpResponseDecryptorTest {

    private Oid4vpResponseDecryptor decryptor;
    private Oid4vpJwk encryptionKey;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpResponseDecryptorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() {
        decryptor = new Oid4vpResponseDecryptor();
        encryptionKey = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
    }

    @Test
    void decrypt_validJwe_returnsVpTokenAndNonce() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String mdocNonce = "wallet-generated-nonce";
        String jwe = encryptPayload(Map.of("vp_token", vpToken), mdocNonce);

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
        assertThat(result.mdocGeneratedNonce()).isEqualTo(mdocNonce);
        assertThat(result.error()).isNull();
    }

    @Test
    void decrypt_walletError_returnsErrorFields() throws Exception {
        String jwe = encryptPayload(Map.of("error", "invalid_scope", "error_description", "Bad scope"), null);

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.error()).isEqualTo("invalid_scope");
        assertThat(result.errorDescription()).isEqualTo("Bad scope");
        assertThat(result.vpToken()).isNull();
    }

    @Test
    void decrypt_nimbusProducedJwe_returnsVpToken() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("test-kid").generate();
        encryptionKey = Oid4vpJwk.parse(key.toJSONString());
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID("test-kid")
                        .build(),
                new Payload(JsonSerialization.writeValueAsString(Map.of("vp_token", vpToken))));
        jwe.encrypt(new ECDHEncrypter(key.toPublicJWK()));

        DecryptedResponse result = decryptor.decrypt(jwe.serialize(), encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
    }

    @Test
    void decrypt_nimbusProducedJweWithBinaryApu_returnsVpToken() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("test-kid").generate();
        encryptionKey = Oid4vpJwk.parse(key.toJSONString());
        byte[] apu = new byte[] {(byte) 0x80, 0x00, 0x01, 0x02, (byte) 0xff};
        byte[] apv = new byte[] {0x10, 0x11, 0x12, 0x13};
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID("test-kid")
                        .agreementPartyUInfo(new Base64URL(Base64URL.encode(apu).toString()))
                        .agreementPartyVInfo(new Base64URL(Base64URL.encode(apv).toString()))
                        .build(),
                new Payload(JsonSerialization.writeValueAsString(Map.of("vp_token", vpToken))));
        jwe.encrypt(new ECDHEncrypter(key.toPublicJWK()));

        DecryptedResponse result = decryptor.decrypt(jwe.serialize(), encryptionKey);

        var header = Oid4vpResponseDecryptor.extractHeader(jwe.serialize());
        assertThat(result.vpToken()).isEqualTo(vpToken);
        assertThat(new String(Base64Url.decode(header.getAgreementPartyUInfo()), StandardCharsets.ISO_8859_1))
                .isEqualTo(new String(apu, StandardCharsets.ISO_8859_1));
        assertThat(new String(Base64Url.decode(header.getAgreementPartyVInfo()), StandardCharsets.ISO_8859_1))
                .isEqualTo(new String(apv, StandardCharsets.ISO_8859_1));
    }

    @Test
    void decrypt_payloadWithIdToken_extractsIdToken() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String idToken = "eyJhbGciOiJFUzI1NiJ9.id-token-payload.sig";
        String jwe = encryptPayload(Map.of("vp_token", vpToken, "id_token", idToken), null);

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
        assertThat(result.idToken()).isEqualTo(idToken);
    }

    @Test
    void decrypt_payloadWithoutIdToken_idTokenIsNull() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String jwe = encryptPayload(Map.of("vp_token", vpToken), null);

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
        assertThat(result.idToken()).isNull();
    }

    @Test
    void decrypt_invalidJwe_throwsIllegalState() {
        assertThatThrownBy(() -> decryptor.decrypt("not-a-jwe", encryptionKey))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void extractKid_validJwe_returnsKid() throws Exception {
        String jwe = encryptPayload(Map.of("vp_token", "test"), null);

        String kid = decryptor.extractKid(jwe);

        assertThat(kid).isEqualTo("test-kid");
    }

    @Test
    void extractKid_noKid_returnsNull() throws Exception {
        Oid4vpJwk noKidKey = new Oid4vpJwk(
                encryptionKey.curve(),
                encryptionKey.x(),
                encryptionKey.y(),
                encryptionKey.privateKey(),
                null,
                encryptionKey.algorithm(),
                encryptionKey.use());
        String payloadJson = JsonSerialization.writeValueAsString(Map.of("vp_token", "test"));
        String jwe =
                Oid4vpRequestObjectEncryptor.encrypt(payloadJson.getBytes(), noKidKey.toPublicJwk(), "A256GCM", null);

        String kid = decryptor.extractKid(jwe);

        assertThat(kid).isNull();
    }

    @Test
    void extractKid_invalidJwe_returnsNull() {
        String kid = decryptor.extractKid("not-a-jwe");

        assertThat(kid).isNull();
    }

    private String encryptPayload(Map<String, Object> payload, String apuNonce) throws Exception {
        String payloadJson = JsonSerialization.writeValueAsString(payload);
        Oid4vpJwk recipientKey = new Oid4vpJwk(
                encryptionKey.curve(),
                encryptionKey.x(),
                encryptionKey.y(),
                null,
                "test-kid",
                encryptionKey.algorithm(),
                encryptionKey.use());
        return encryptPayload(payloadJson, recipientKey, apuNonce);
    }

    private static String encryptPayload(String payloadJson, Oid4vpJwk recipientKey, String apuNonce) {
        try {
            JWEHeader.Builder header =
                    new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).keyID(recipientKey.keyId());
            if (apuNonce != null) {
                header.agreementPartyUInfo(
                        new Base64URL(Base64URL.encode(apuNonce).toString()));
            }
            JWEObject jwe = new JWEObject(header.build(), new Payload(payloadJson));
            ECKey publicKey = ECKey.parse(recipientKey.toPublicJwk().toJson());
            jwe.encrypt(new ECDHEncrypter(publicKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt test payload", e);
        }
    }
}
