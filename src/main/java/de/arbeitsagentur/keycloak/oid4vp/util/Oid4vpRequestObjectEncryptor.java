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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;

/**
 * Encrypts a signed request object JWT into a JWE using the wallet's encryption key
 * from wallet_metadata. Produces a nested JWT (sign-then-encrypt) per RFC 7516.
 */
public final class Oid4vpRequestObjectEncryptor {

    private Oid4vpRequestObjectEncryptor() {}

    public static String encrypt(String signedJwt, WalletMetadata walletMetadata) {
        try {
            JWEHeader.Builder headerBuilder = new JWEHeader.Builder(
                            walletMetadata.algorithm(), walletMetadata.encryptionMethod())
                    .contentType(Oid4vpConstants.REQUEST_OBJECT_TYP);

            if (walletMetadata.encryptionKey().getKeyID() != null) {
                headerBuilder.keyID(walletMetadata.encryptionKey().getKeyID());
            }

            JWEObject jwe = new JWEObject(headerBuilder.build(), new Payload(signedJwt));
            jwe.encrypt(new ECDHEncrypter(walletMetadata.encryptionKey()));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to encrypt request object: " + e.getMessage(), e);
        }
    }
}
