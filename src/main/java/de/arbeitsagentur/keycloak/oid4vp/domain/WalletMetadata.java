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
import org.keycloak.util.JsonSerialization;

/**
 * Parsed {@code wallet_metadata} from a wallet's POST to the request-object endpoint.
 *
 * <p>In the OID4VP redirect flow, a wallet may optionally include a {@code wallet_metadata} form
 * parameter when fetching the request object (POST to {@code /request-object/{handle}}). This
 * metadata advertises the wallet's encryption capabilities — specifically, which JWE algorithms
 * and content encryption methods it supports, along with a public key the verifier must use to
 * encrypt the request object before returning it.
 *
 * <p>When present, the verifier is required to encrypt the signed request object JWT into a JWE
 * (sign-then-encrypt). This record holds the negotiated algorithm, encryption method, and the
 * wallet's EC public key extracted from the metadata JSON.
 *
 * @see de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectEncryptor
 */
public record WalletMetadata(Oid4vpJwk encryptionKey, String algorithm, String encryptionMethod) {

    /**
     * Parses the raw {@code wallet_metadata} JSON string from the form parameter.
     *
     * <p>Extracts the first EC key from {@code jwks.keys}, and negotiates the JWE algorithm and
     * content encryption method by intersecting the wallet's advertised values with our supported
     * set (ECDH-ES + A128GCM/A256GCM). Defaults to ECDH-ES and A128GCM when the wallet omits
     * the algorithm/encryption fields.
     *
     * @throws IllegalArgumentException if the JSON is invalid, contains no EC key, or advertises
     *     only unsupported algorithms
     */
    @SuppressWarnings("unchecked")
    public static WalletMetadata parse(String walletMetadataJson) {
        Map<String, Object> metadata;
        try {
            metadata = JsonSerialization.readValue(walletMetadataJson, Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid wallet_metadata JSON: " + e.getMessage(), e);
        }

        Oid4vpJwk encryptionKey = extractEncryptionKey(metadata);
        String algorithm = selectAlgorithm(metadata);
        String encryptionMethod = selectEncryptionMethod(metadata);

        return new WalletMetadata(encryptionKey, algorithm, encryptionMethod);
    }

    @SuppressWarnings("unchecked")
    private static Oid4vpJwk extractEncryptionKey(Map<String, Object> metadata) {
        Object jwksObj = metadata.get("jwks");
        if (jwksObj == null) {
            throw new IllegalArgumentException("wallet_metadata missing 'jwks'");
        }

        try {
            Map<String, Object> jwks = JsonSerialization.mapper.convertValue(jwksObj, Map.class);
            Object keysObj = jwks.get("keys");
            if (!(keysObj instanceof List<?> keys)) {
                throw new IllegalArgumentException("wallet_metadata jwks missing keys");
            }
            for (Object key : keys) {
                if (key instanceof Map<?, ?> map) {
                    return Oid4vpJwk.parse((Map<String, Object>) map);
                }
            }
            throw new IllegalArgumentException("No EC key found in wallet_metadata jwks");
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e;
            throw new IllegalArgumentException("Failed to process wallet_metadata jwks: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private static String selectAlgorithm(Map<String, Object> metadata) {
        Object algValues = metadata.get("authorization_encryption_alg_values_supported");
        if (algValues instanceof List<?> algList) {
            for (Object alg : algList) {
                String candidate = alg.toString();
                if (Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS.contains(candidate)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException(
                    "No supported algorithm in authorization_encryption_alg_values_supported: " + algList
                            + ". Supported: " + Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS);
        }
        // Default to ECDH-ES if not specified
        return "ECDH-ES";
    }

    @SuppressWarnings("unchecked")
    private static String selectEncryptionMethod(Map<String, Object> metadata) {
        Object encValues = metadata.get("authorization_encryption_enc_values_supported");
        if (encValues instanceof List<?> encList) {
            for (Object enc : encList) {
                String candidate = enc.toString();
                if (Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_METHODS.contains(candidate)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException(
                    "No supported encryption method in authorization_encryption_enc_values_supported: " + encList
                            + ". Supported: " + Oid4vpConstants.SUPPORTED_REQUEST_OBJECT_ENCRYPTION_METHODS);
        }
        // Default to A128GCM if not specified
        return "A128GCM";
    }
}
