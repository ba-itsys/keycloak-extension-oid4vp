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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oid4vp.ResponseEncryption;
import org.keycloak.common.crypto.CryptoIntegration;

class Oid4vpRequestObjectEncryptorTest {

    private Oid4vpJwk walletKey;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpRequestObjectEncryptorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() {
        walletKey = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
        walletKey = new Oid4vpJwk(
                walletKey.curve(),
                walletKey.x(),
                walletKey.y(),
                walletKey.privateKey(),
                "wallet-enc-key",
                walletKey.algorithm(),
                walletKey.use());
    }

    @Test
    void encrypt_producesValidJwe_decryptableWithPrivateKey() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        String content = ResponseEncryption.decrypt(ResponseEncryption.parse(encrypted), walletKey.toPrivateKey());
        assertThat(content).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_setsContentTypeHeader() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        assertThat(ResponseEncryption.parse(encrypted).header().getContentType())
                .isEqualTo("JWT");
    }

    @Test
    void encrypt_usesWalletKeyId() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        assertThat(ResponseEncryption.parse(encrypted).header().getKeyId()).isEqualTo("wallet-enc-key");
    }

    @Test
    void encrypt_withA256gcm_usesCorrectEncryptionMethod() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A256GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        String content = ResponseEncryption.decrypt(ResponseEncryption.parse(encrypted), walletKey.toPrivateKey());
        assertThat(ResponseEncryption.parse(encrypted).header().getEncryptionAlgorithm())
                .isEqualTo("A256GCM");
        assertThat(content).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_withoutKeyId_omitsKidInHeader() throws Exception {
        Oid4vpJwk noKidKey = new Oid4vpJwk(
                walletKey.curve(), walletKey.x(), walletKey.y(), walletKey.privateKey(), null, "ECDH-ES", "enc");
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(noKidKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        String content = ResponseEncryption.decrypt(ResponseEncryption.parse(encrypted), noKidKey.toPrivateKey());
        assertThat(ResponseEncryption.parse(encrypted).header().getKeyId()).isNull();
        assertThat(content).isEqualTo(signedJwt);
    }
}
