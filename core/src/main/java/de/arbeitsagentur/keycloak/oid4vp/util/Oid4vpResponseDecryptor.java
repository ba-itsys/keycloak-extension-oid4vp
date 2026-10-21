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

import static org.keycloak.OID4VCConstants.VP_TOKEN;

import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oid4vp.EphemeralKey;
import org.keycloak.broker.oid4vp.ParsedResponse;
import org.keycloak.broker.oid4vp.ResponseEncryption;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.util.JsonSerialization;

/**
 * Decrypts wallet responses sent in the {@code direct_post.jwt} response mode. The verifier
 * advertises an ephemeral encryption key per flow in the request object's {@code client_metadata},
 * and the JWE header kid of the response names the key the wallet used.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1">OID4VP 1.0 §8.3.1, Response Mode direct_post.jwt</a>
 */
public class Oid4vpResponseDecryptor {

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseDecryptor.class);

    /**
     * Reads the JWE key id header without decrypting. Since the value only selects a candidate
     * decryption key, this stays tolerant and returns {@code null} for malformed input, while
     * {@link #decrypt(String, EphemeralKey)} remains strict and rejects it.
     */
    public String extractKid(String encryptedResponse) {
        String kid;
        try {
            kid = ResponseEncryption.parse(encryptedResponse).keyId();
        } catch (Exception e) {
            LOG.warnf("Failed to read the kid header of the wallet response JWE: %s", FailureDetails.causeChain(e));
            return null;
        }
        if (kid == null) {
            LOG.warn("The wallet response JWE carries no kid header");
        }
        return kid;
    }

    public DecryptedResponse decrypt(String encryptedResponse, EphemeralKey decryptionKey) {
        try {
            ParsedResponse parsed = ResponseEncryption.parse(encryptedResponse);
            String payload = ResponseEncryption.decrypt(parsed, decryptionKey.privateKey());

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            String state = stringValue(payloadMap.get(OAuth2Constants.STATE));

            Object errorObj = payloadMap.get(OAuth2Constants.ERROR);
            if (errorObj != null) {
                Object errorDescObj = payloadMap.get(OAuth2Constants.ERROR_DESCRIPTION);
                return new DecryptedResponse(
                        null, state, errorObj.toString(), errorDescObj != null ? errorDescObj.toString() : null);
            }

            String vpToken = null;
            Object vpTokenObj = payloadMap.get(VP_TOKEN);
            if (vpTokenObj != null) {
                vpToken = vpTokenObj instanceof String s ? s : JsonSerialization.writeValueAsString(vpTokenObj);
            }

            return new DecryptedResponse(vpToken, state, null, null);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to decrypt response: " + FailureDetails.causeChain(e) + " ("
                            + describeHeader(encryptedResponse) + ", decryption key kid="
                            + (decryptionKey != null ? decryptionKey.kid() : null) + ")",
                    e);
        }
    }

    private static String describeHeader(String compactJwe) {
        try {
            JWEHeader header = ResponseEncryption.parse(compactJwe).header();
            return FailureDetails.singleLine("alg=" + header.getAlgorithm() + ", enc=" + header.getEncryptionAlgorithm()
                    + ", kid=" + header.getKeyId());
        } catch (Exception e) {
            return "unreadable JWE header";
        }
    }

    private static String stringValue(Object value) {
        return value != null ? value.toString() : null;
    }
}
