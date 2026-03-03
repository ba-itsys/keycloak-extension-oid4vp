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
 * Encrypts a signed request object JWT into a JWE using the wallet's encryption key from
 * {@code wallet_metadata}. This is the counterpart to {@link Oid4vpResponseDecryptor} — while
 * that class decrypts wallet responses, this class encrypts verifier request objects.
 *
 * <p>Called from {@code Oid4vpIdentityProviderEndpoint.generateRequestObject} when the wallet
 * includes {@code wallet_metadata} in its POST to the request-object endpoint. The result is a
 * nested JWT: the signed request object (JWS) wrapped in a JWE, with {@code cty: oauth-authz-req+jwt}
 * per RFC 7516 §4.1.12 to indicate the inner content type.
 */
public final class Oid4vpRequestObjectEncryptor {

    private Oid4vpRequestObjectEncryptor() {}

    /**
     * Wraps a signed request object JWT in a JWE encrypted with the wallet's public key.
     *
     * @param signedJwt the compact-serialized signed JWT (JWS) produced by
     *     {@link de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService#buildSignedRequestObject}
     * @param walletMetadata the parsed wallet metadata containing the encryption key and negotiated algorithms
     * @return the compact-serialized JWE string
     */
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
