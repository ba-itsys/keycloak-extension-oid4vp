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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.VP_TOKEN;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.util.JsonSerialization;

/**
 * Decrypts wallet responses encrypted with {@code direct_post.jwt} response mode.
 *
 * <p>When HAIP is enabled, the verifier includes an ephemeral encryption key in the request
 * object's {@code client_metadata}. The wallet encrypts its response (containing the
 * {@code vp_token}) as a JWE using that key. This class extracts the KID from the JWE header
 * to look up the matching private key, then decrypts the payload.
 *
 * <p>Also extracts the {@code apu} (Agreement PartyUInfo) header for mDoc-specific nonce handling.
 *
 * @see Oid4vpRequestObjectEncryptor the inverse operation (encrypting request objects for wallets)
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Response Mode direct_post.jwt</a>
 */
public class Oid4vpResponseDecryptor {

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseDecryptor.class);

    /** Extracts the JWE Key ID header without decrypting, used to look up the decryption key. */
    public String extractKid(String encryptedResponse) {
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            return jwe.getHeader().getKeyID();
        } catch (Exception e) {
            LOG.warnf("Failed to extract KID from JWE: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Decrypts a JWE-encrypted wallet response and extracts the {@code vp_token} or error.
     *
     * @param encryptedResponse the compact-serialized JWE from the wallet's direct_post.jwt response
     * @param decryptionKey the ephemeral EC private key that was advertised in the request object
     * @return the decrypted response containing the VP token, mDoc nonce, or error details
     */
    public DecryptedResponse decrypt(String encryptedResponse, ECKey decryptionKey) {
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            jwe.decrypt(new ECDHDecrypter(decryptionKey));
            String payload = jwe.getPayload().toString();

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            String mdocGeneratedNonce = null;
            Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
            if (apu != null) {
                mdocGeneratedNonce = apu.decodeToString();
            }

            Object errorObj = payloadMap.get(OAuth2Constants.ERROR);
            if (errorObj != null) {
                Object errorDescObj = payloadMap.get(OAuth2Constants.ERROR_DESCRIPTION);
                return new DecryptedResponse(
                        null,
                        mdocGeneratedNonce,
                        errorObj.toString(),
                        errorDescObj != null ? errorDescObj.toString() : null);
            }

            String vpToken = null;
            Object vpTokenObj = payloadMap.get(VP_TOKEN);
            if (vpTokenObj != null) {
                vpToken = vpTokenObj instanceof String s ? s : JsonSerialization.writeValueAsString(vpTokenObj);
            }

            return new DecryptedResponse(vpToken, mdocGeneratedNonce, null, null);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt response: " + e.getMessage(), e);
        }
    }
}
