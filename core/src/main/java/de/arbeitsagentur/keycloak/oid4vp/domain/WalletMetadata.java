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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.util.JsonSerialization;

/**
 * The encryption a wallet asks for in the {@code wallet_metadata} it may send when it fetches the
 * request object.
 *
 * <p>A wallet that requires an encrypted request object passes its public encryption keys in the
 * {@code jwks} member of that metadata (OID4VP 1.0 §5.10), so metadata without such a key
 * describes a wallet that takes the signed request object as it is and no instance of this record
 * exists for it.
 *
 * @see de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectEncryptor
 */
public record WalletMetadata(Oid4vpJwk encryptionKey, String algorithm, String encryptionMethod) {

    private static final Logger LOG = Logger.getLogger(WalletMetadata.class);

    private static final String DEFAULT_ENCRYPTION_ALGORITHM = "ECDH-ES";
    private static final String DEFAULT_ENCRYPTION_METHOD = "A128GCM";

    /**
     * Returns the encryption the given {@code wallet_metadata} asks for, empty when it names no
     * key the request object can be encrypted to. The JWE algorithm comes from the key itself,
     * because a JWK carries the algorithm it is meant for.
     *
     * @throws IllegalArgumentException when the metadata is not valid JSON or its {@code jwks}
     *     member is malformed
     */
    @SuppressWarnings("unchecked")
    public static Optional<WalletMetadata> encryptionRequestedBy(String walletMetadataJson) {
        Map<String, Object> metadata;
        try {
            metadata = JsonSerialization.readValue(walletMetadataJson, Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid wallet_metadata JSON: " + e.getMessage(), e);
        }

        return extractEncryptionKey(metadata)
                .map(encryptionKey -> new WalletMetadata(
                        encryptionKey, algorithmOf(encryptionKey), selectEncryptionMethod(metadata)));
    }

    /**
     * Returns the first key of the metadata the request object can be encrypted to. A key
     * qualifies when it is an EC key on a supported curve whose {@code use} does not reserve it
     * for another purpose and whose {@code alg} does not bind it to an unsupported algorithm, so
     * that a wallet publishing its signing key next to its encryption key is read correctly.
     */
    @SuppressWarnings("unchecked")
    private static Optional<Oid4vpJwk> extractEncryptionKey(Map<String, Object> metadata) {
        Object jwksObj = metadata.get("jwks");
        if (jwksObj == null) {
            return Optional.empty();
        }

        try {
            Map<String, Object> jwks = JsonSerialization.mapper.convertValue(jwksObj, Map.class);
            Object keysObj = jwks.get("keys");
            if (!(keysObj instanceof List<?> keys)) {
                throw new IllegalArgumentException("wallet_metadata jwks missing keys");
            }
            for (Object key : keys) {
                if (key instanceof Map<?, ?> map) {
                    Oid4vpJwk usableKey = usableEncryptionKey((Map<String, Object>) map);
                    if (usableKey != null) {
                        return Optional.of(usableKey);
                    }
                }
            }
            return Optional.empty();
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException illegalArgument) throw illegalArgument;
            throw new IllegalArgumentException("Failed to process wallet_metadata jwks: " + e.getMessage(), e);
        }
    }

    private static Oid4vpJwk usableEncryptionKey(Map<String, Object> rawKey) {
        Oid4vpJwk key;
        try {
            key = Oid4vpJwk.parse(rawKey);
            // Reading the point out rejects an unsupported curve and malformed coordinates while
            // another key can still take over, which is impossible once encryption starts.
            key.toPublicKey();
        } catch (IllegalArgumentException e) {
            LOG.debugf("Skipping unusable wallet_metadata key: %s", e.getMessage());
            return null;
        }
        if (key.use() != null && !KeyUse.ENC.getSpecName().equals(key.use())) {
            LOG.debugf("Skipping wallet_metadata key '%s' published for use '%s'", key.keyId(), key.use());
            return null;
        }
        if (key.algorithm() != null
                && !Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS.contains(key.algorithm())) {
            LOG.debugf(
                    "Skipping wallet_metadata key '%s' bound to the unsupported algorithm '%s'",
                    key.keyId(), key.algorithm());
            return null;
        }
        return key;
    }

    private static String algorithmOf(Oid4vpJwk encryptionKey) {
        return encryptionKey.algorithm() != null ? encryptionKey.algorithm() : DEFAULT_ENCRYPTION_ALGORITHM;
    }

    /**
     * Selects the content encryption method the request object is encrypted with, reading
     * {@code request_object_encryption_enc_values_supported}. The wallet is the authorization
     * server of the flow, and OID4VP 1.0 §5.10.1 delegates the request object to RFC 9101, which
     * defines that parameter. The {@code authorization_encryption_*} parameters describe the
     * authorization response (OID4VP 1.0 §5.10) and say nothing about the request object, so they
     * are not read here.
     *
     * <p>The advertisement is a preference and not a demand, so a wallet advertising only
     * unsupported methods still receives a request object it may attempt to decrypt. No
     * specification defines a default for this direction, so A128GCM is applied, which OID4VP 1.0
     * §8.3 names as the default for the encrypted response. The JWE header states the chosen
     * method, which lets the wallet decrypt without prior agreement.
     */
    private static String selectEncryptionMethod(Map<String, Object> metadata) {
        if (metadata.get("request_object_encryption_enc_values_supported") instanceof List<?> encList) {
            for (Object enc : encList) {
                String candidate = enc.toString();
                if (Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_METHODS.contains(candidate)) {
                    return candidate;
                }
            }
            LOG.debugf("wallet_metadata advertises no supported request object encryption method (%s)", encList);
        }
        return DEFAULT_ENCRYPTION_METHOD;
    }
}
