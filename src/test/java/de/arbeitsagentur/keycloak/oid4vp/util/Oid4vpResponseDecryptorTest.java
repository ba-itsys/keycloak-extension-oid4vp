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

import static org.assertj.core.api.Assertions.*;

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
import de.arbeitsagentur.keycloak.oid4vp.domain.PreDecryptionResult;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

class Oid4vpResponseDecryptorTest {

    private Oid4vpResponseDecryptor decryptor;
    private ECKey encryptionKey;

    @BeforeEach
    void setUp() throws Exception {
        decryptor = new Oid4vpResponseDecryptor();
        encryptionKey = new ECKeyGenerator(Curve.P_256).keyID("test-kid").generate();
    }

    @Test
    void decryptFull_validJwe_returnsVpTokenAndNonce() throws Exception {
        String vpToken = "eyJhbGciOiJFUzI1NiJ9.test.sig~";
        String mdocNonce = "wallet-generated-nonce";
        String jwe = encryptPayload(Map.of("vp_token", vpToken), mdocNonce);

        DecryptedResponse result = decryptor.decryptFull(jwe, encryptionKey.toJSONString());

        assertThat(result.vpToken()).isEqualTo(vpToken);
        // apu is Base64URL-encoded in the JWE header; the decryptor returns the raw Base64URL string
        assertThat(result.mdocGeneratedNonce())
                .isEqualTo(Base64URL.encode(mdocNonce).toString());
        assertThat(result.error()).isNull();
    }

    @Test
    void decryptFull_walletError_returnsErrorFields() throws Exception {
        String jwe = encryptPayload(Map.of("error", "invalid_scope", "error_description", "Bad scope"), null);

        DecryptedResponse result = decryptor.decryptFull(jwe, encryptionKey.toJSONString());

        assertThat(result.error()).isEqualTo("invalid_scope");
        assertThat(result.errorDescription()).isEqualTo("Bad scope");
        assertThat(result.vpToken()).isNull();
    }

    @Test
    void decryptFull_blankKey_throwsIllegalState() {
        assertThatThrownBy(() -> decryptor.decryptFull("jwe", "")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void tryPreDecrypt_noKid_returnsEmpty() throws Exception {
        // JWE without kid in header
        ECKey noKidKey = new ECKeyGenerator(Curve.P_256).generate();
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build();
        JWEObject jwe = new JWEObject(header, new Payload("{\"vp_token\":\"test\"}"));
        jwe.encrypt(new ECDHEncrypter(noKidKey));

        PreDecryptionResult result = decryptor.tryPreDecrypt(jwe.serialize(), null, null);

        assertThat(result).isEqualTo(PreDecryptionResult.EMPTY);
    }

    @Test
    void tryPreDecrypt_invalidJwe_returnsEmpty() {
        PreDecryptionResult result = decryptor.tryPreDecrypt("not-a-jwe", null, null);

        assertThat(result).isEqualTo(PreDecryptionResult.EMPTY);
    }

    private String encryptPayload(Map<String, Object> payload, String apuNonce) throws Exception {
        String payloadJson = JsonSerialization.writeValueAsString(payload);
        JWEHeader.Builder headerBuilder =
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).keyID("test-kid");
        if (apuNonce != null) {
            headerBuilder.agreementPartyUInfo(Base64URL.encode(apuNonce));
        }
        JWEObject jwe = new JWEObject(headerBuilder.build(), new Payload(payloadJson));
        jwe.encrypt(new ECDHEncrypter(encryptionKey.toPublicJWK()));
        return jwe.serialize();
    }
}
