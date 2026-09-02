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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import java.nio.charset.StandardCharsets;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEHeader;

/**
 * Encrypts a signed request object into a JWE for the wallet's key from {@code wallet_metadata}.
 * The result is a nested JWT, so it carries {@code cty: oauth-authz-req+jwt} to declare the inner
 * content type per RFC 7516 §4.1.12.
 */
public final class Oid4vpRequestObjectEncryptor {

    private Oid4vpRequestObjectEncryptor() {}

    public static String encrypt(String signedJwt, WalletMetadata walletMetadata) {
        try {
            return encrypt(
                    signedJwt.getBytes(StandardCharsets.UTF_8),
                    walletMetadata.encryptionKey(),
                    walletMetadata.algorithm(),
                    walletMetadata.encryptionMethod(),
                    Oid4vpConstants.REQUEST_OBJECT_TYP);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt request object: " + e.getMessage(), e);
        }
    }

    static String encrypt(
            byte[] plaintext, Oid4vpJwk recipientKey, String algorithm, String encryptionMethod, String contentType) {
        try {
            JWEHeader.JWEHeaderBuilder header = JWEHeader.builder()
                    .algorithm(algorithm)
                    .encryptionAlgorithm(encryptionMethod)
                    .contentType(contentType);
            if (recipientKey.keyId() != null) {
                header.keyId(recipientKey.keyId());
            }

            JWE jwe = new JWE().header(header.build()).content(plaintext);
            jwe.getKeyStorage().setEncryptionKey(recipientKey.toPublicKey());
            return jwe.encodeJwe();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt JWE", e);
        }
    }
}
