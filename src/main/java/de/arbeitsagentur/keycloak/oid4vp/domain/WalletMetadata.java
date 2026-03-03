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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * @see Oid4vpRequestObjectEncryptor
 */
public record WalletMetadata(ECKey encryptionKey, JWEAlgorithm algorithm, EncryptionMethod encryptionMethod) {

    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.ECDH_ES);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);

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

        ECKey encryptionKey = extractEncryptionKey(metadata);
        JWEAlgorithm algorithm = selectAlgorithm(metadata);
        EncryptionMethod encryptionMethod = selectEncryptionMethod(metadata);

        return new WalletMetadata(encryptionKey, algorithm, encryptionMethod);
    }

    @SuppressWarnings("unchecked")
    private static ECKey extractEncryptionKey(Map<String, Object> metadata) {
        Object jwksObj = metadata.get("jwks");
        if (jwksObj == null) {
            throw new IllegalArgumentException("wallet_metadata missing 'jwks'");
        }

        try {
            String jwksJson = JsonSerialization.writeValueAsString(jwksObj);
            JWKSet jwkSet = JWKSet.parse(jwksJson);
            for (JWK jwk : jwkSet.getKeys()) {
                if (jwk instanceof ECKey ecKey) {
                    return ecKey;
                }
            }
            throw new IllegalArgumentException("No EC key found in wallet_metadata jwks");
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse wallet_metadata jwks: " + e.getMessage(), e);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e;
            throw new IllegalArgumentException("Failed to process wallet_metadata jwks: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private static JWEAlgorithm selectAlgorithm(Map<String, Object> metadata) {
        Object algValues = metadata.get("authorization_encryption_alg_values_supported");
        if (algValues instanceof List<?> algList) {
            for (Object alg : algList) {
                JWEAlgorithm candidate = JWEAlgorithm.parse(alg.toString());
                if (SUPPORTED_ALGORITHMS.contains(candidate)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException(
                    "No supported algorithm in authorization_encryption_alg_values_supported: " + algList
                            + ". Supported: " + SUPPORTED_ALGORITHMS);
        }
        // Default to ECDH-ES if not specified
        return JWEAlgorithm.ECDH_ES;
    }

    @SuppressWarnings("unchecked")
    private static EncryptionMethod selectEncryptionMethod(Map<String, Object> metadata) {
        Object encValues = metadata.get("authorization_encryption_enc_values_supported");
        if (encValues instanceof List<?> encList) {
            for (Object enc : encList) {
                EncryptionMethod candidate = EncryptionMethod.parse(enc.toString());
                if (SUPPORTED_ENCRYPTION_METHODS.contains(candidate)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException(
                    "No supported encryption method in authorization_encryption_enc_values_supported: " + encList
                            + ". Supported: " + SUPPORTED_ENCRYPTION_METHODS);
        }
        // Default to A128GCM if not specified
        return EncryptionMethod.A128GCM;
    }
}
