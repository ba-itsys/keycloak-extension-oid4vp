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
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Oid4vpRequestObjectEncryptorTest {

    private ECKey walletKey;

    @BeforeEach
    void setUp() throws Exception {
        walletKey = new ECKeyGenerator(Curve.P_256).keyID("wallet-enc-key").generate();
    }

    @Test
    void encrypt_producesValidJwe_decryptableWithPrivateKey() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature";
        WalletMetadata metadata =
                new WalletMetadata(walletKey.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM);

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWEObject jwe = JWEObject.parse(encrypted);
        jwe.decrypt(new ECDHDecrypter(walletKey));
        assertThat(jwe.getPayload().toString()).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_setsContentTypeHeader() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata =
                new WalletMetadata(walletKey.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM);

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWEObject jwe = JWEObject.parse(encrypted);
        assertThat(jwe.getHeader().getContentType()).isEqualTo(Oid4vpConstants.REQUEST_OBJECT_TYP);
    }

    @Test
    void encrypt_usesWalletKeyId() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata =
                new WalletMetadata(walletKey.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM);

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWEObject jwe = JWEObject.parse(encrypted);
        assertThat(jwe.getHeader().getKeyID()).isEqualTo("wallet-enc-key");
    }

    @Test
    void encrypt_withA256gcm_usesCorrectEncryptionMethod() throws Exception {
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata =
                new WalletMetadata(walletKey.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM);

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWEObject jwe = JWEObject.parse(encrypted);
        assertThat(jwe.getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);

        jwe.decrypt(new ECDHDecrypter(walletKey));
        assertThat(jwe.getPayload().toString()).isEqualTo(signedJwt);
    }

    @Test
    void encrypt_withoutKeyId_omitsKidInHeader() throws Exception {
        ECKey noKidKey = new ECKeyGenerator(Curve.P_256).generate();
        String signedJwt = "eyJhbGciOiJFUzI1NiJ9.test.sig";
        WalletMetadata metadata =
                new WalletMetadata(noKidKey.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM);

        String encrypted = Oid4vpRequestObjectEncryptor.encrypt(signedJwt, metadata);

        JWEObject jwe = JWEObject.parse(encrypted);
        assertThat(jwe.getHeader().getKeyID()).isNull();

        jwe.decrypt(new ECDHDecrypter(noKidKey));
        assertThat(jwe.getPayload().toString()).isEqualTo(signedJwt);
    }
}
