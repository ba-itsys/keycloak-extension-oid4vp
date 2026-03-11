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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwe.JWE;

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
    void encrypt_producesValidJwe_decryptableWithPrivateKey() {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWE jwe = Oid4vpResponseDecryptor.decryptJwe(encrypted, walletKey);
        assertThat(new String(jwe.getContent(), StandardCharsets.UTF_8)).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_setsContentTypeHeader() {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        assertThat(Oid4vpResponseDecryptor.extractHeader(encrypted).getContentType())
                .isEqualTo(Oid4vpConstants.REQUEST_OBJECT_TYP);
    }

    @Test
    void encrypt_usesWalletKeyId() {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        assertThat(Oid4vpResponseDecryptor.extractHeader(encrypted).getKeyId()).isEqualTo("wallet-enc-key");
    }

    @Test
    void encrypt_withA256gcm_usesCorrectEncryptionMethod() {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(walletKey.toPublicJwk(), "ECDH-ES", "A256GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWE jwe = Oid4vpResponseDecryptor.decryptJwe(encrypted, walletKey);
        assertThat(Oid4vpResponseDecryptor.extractHeader(encrypted).getEncryptionAlgorithm())
                .isEqualTo("A256GCM");
        assertThat(new String(jwe.getContent(), StandardCharsets.UTF_8)).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_withoutKeyId_omitsKidInHeader() {
        Oid4vpJwk noKidKey = new Oid4vpJwk(
                walletKey.curve(), walletKey.x(), walletKey.y(), walletKey.privateKey(), null, "ECDH-ES", "enc");
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata = new WalletMetadata(noKidKey.toPublicJwk(), "ECDH-ES", "A128GCM");

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWE jwe = Oid4vpResponseDecryptor.decryptJwe(encrypted, noKidKey);
        assertThat(Oid4vpResponseDecryptor.extractHeader(encrypted).getKeyId()).isNull();
        assertThat(new String(jwe.getContent(), StandardCharsets.UTF_8)).isEqualTo(signedJwt);
    }
}
