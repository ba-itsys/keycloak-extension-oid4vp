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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oid4vp.EphemeralKey;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.util.JsonSerialization;

class Oid4vpResponseDecryptorTest {

    private Oid4vpResponseDecryptor decryptor;
    private EphemeralKey encryptionKey;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpResponseDecryptorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() {
        decryptor = new Oid4vpResponseDecryptor();
        encryptionKey = EphemeralKey.generate("test-kid");
    }

    @Test
    void decrypt_validJwe_returnsVpToken() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String jwe = encryptPayload(Map.of("vp_token", vpToken));

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
        assertThat(result.error()).isNull();
    }

    @Test
    void decrypt_walletError_returnsErrorFields() throws Exception {
        String jwe = encryptPayload(Map.of("error", "invalid_scope", "error_description", "Bad scope"));

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.error()).isEqualTo("invalid_scope");
        assertThat(result.errorDescription()).isEqualTo("Bad scope");
        assertThat(result.vpToken()).isNull();
    }

    @Test
    void decrypt_nimbusProducedJwe_returnsVpToken() throws Exception {
        ECKey key = ECKey.parse(JsonSerialization.writeValueAsString(encryptionKey.publicJwk()));
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
        ECKey key = ECKey.parse(JsonSerialization.writeValueAsString(encryptionKey.publicJwk()));
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

        assertThat(result.vpToken()).isEqualTo(vpToken);
    }

    @Test
    void decrypt_payloadWithIdToken_ignoresIt() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String jwe =
                encryptPayload(Map.of("vp_token", vpToken, "id_token", "eyJhbGciOiJFUzI1NiJ9.id-token-payload.sig"));

        DecryptedResponse result = decryptor.decrypt(jwe, encryptionKey);

        assertThat(result.vpToken()).isEqualTo(vpToken);
    }

    @Test
    void decrypt_invalidJwe_throwsIllegalState() {
        assertThatThrownBy(() -> decryptor.decrypt("not-a-jwe", encryptionKey))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void extractKid_validJwe_returnsKid() throws Exception {
        String jwe = encryptPayload(Map.of("vp_token", "test"));

        String kid = decryptor.extractKid(jwe);

        assertThat(kid).isEqualTo("test-kid");
    }

    @Test
    void extractKid_noKid_returnsNull() throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build(),
                new Payload(JsonSerialization.writeValueAsString(Map.of("vp_token", "test"))));
        jwe.encrypt(new ECDHEncrypter(ECKey.parse(JsonSerialization.writeValueAsString(encryptionKey.publicJwk()))));

        String kid = decryptor.extractKid(jwe.serialize());

        assertThat(kid).isNull();
    }

    @Test
    void extractKid_invalidJwe_returnsNull() {
        String kid = decryptor.extractKid("not-a-jwe");

        assertThat(kid).isNull();
    }

    private String encryptPayload(Map<String, Object> payload) throws Exception {
        String payloadJson = JsonSerialization.writeValueAsString(payload);
        return encryptPayload(payloadJson, encryptionKey);
    }

    private static String encryptPayload(String payloadJson, EphemeralKey recipientKey) {
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .keyID(recipientKey.kid())
                    .build();
            JWEObject jwe = new JWEObject(header, new Payload(payloadJson));
            ECKey publicKey = ECKey.parse(JsonSerialization.writeValueAsString(recipientKey.publicJwk()));
            jwe.encrypt(new ECDHEncrypter(publicKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt test payload", e);
        }
    }
}
