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

import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.util.JsonSerialization;

/**
 * Decrypts wallet responses sent in the {@code direct_post.jwt} response mode. The verifier
 * advertises an ephemeral encryption key per flow in the request object's {@code client_metadata},
 * and the JWE header kid of the response names the key the wallet used. The {@code apu} (Agreement
 * PartyUInfo) header carries the nonce the wallet generated for mDoc session transcripts.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1">OID4VP 1.0 §8.3.1, Response Mode direct_post.jwt</a>
 */
public class Oid4vpResponseDecryptor {

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseDecryptor.class);

    /**
     * Reads the JWE key id header without decrypting. Since the value only selects a candidate
     * decryption key, this stays tolerant and returns {@code null} for malformed input, while
     * {@link #decrypt(String, Oid4vpJwk)} remains strict and rejects it.
     */
    public String extractKid(String encryptedResponse) {
        String kid;
        try {
            kid = extractHeader(encryptedResponse).getKeyId();
        } catch (Exception e) {
            LOG.warn("Failed to extract KID from JWE");
            return null;
        }
        if (kid == null) {
            LOG.warn("Failed to extract KID from JWE");
        }
        return kid;
    }

    public DecryptedResponse decrypt(String encryptedResponse, Oid4vpJwk decryptionKey) {
        try {
            JWE jwe = decryptJwe(encryptedResponse, decryptionKey);
            JWEHeader header = (JWEHeader) jwe.getHeader();
            String payload = new String(jwe.getContent(), StandardCharsets.UTF_8);

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            String mdocGeneratedNonce = decodeHeaderValue(header.getAgreementPartyUInfo());
            String state = stringValue(payloadMap.get(OAuth2Constants.STATE));

            Object errorObj = payloadMap.get(OAuth2Constants.ERROR);
            if (errorObj != null) {
                Object errorDescObj = payloadMap.get(OAuth2Constants.ERROR_DESCRIPTION);
                return new DecryptedResponse(
                        null,
                        state,
                        mdocGeneratedNonce,
                        errorObj.toString(),
                        errorDescObj != null ? errorDescObj.toString() : null);
            }

            String vpToken = null;
            Object vpTokenObj = payloadMap.get(VP_TOKEN);
            if (vpTokenObj != null) {
                vpToken = vpTokenObj instanceof String s ? s : JsonSerialization.writeValueAsString(vpTokenObj);
            }

            return new DecryptedResponse(vpToken, state, mdocGeneratedNonce, null, null);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt response: " + e.getMessage(), e);
        }
    }

    static JWE decryptJwe(String compactJwe, Oid4vpJwk recipientKey) {
        try {
            JWE jwe = new JWE();
            jwe.getKeyStorage().setDecryptionKey(recipientKey.toPrivateKey());
            jwe.verifyAndDecodeJwe(compactJwe);
            return jwe;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt JWE", e);
        }
    }

    static JWEHeader extractHeader(String compactJwe) {
        return (JWEHeader) new JWE(compactJwe).getHeader();
    }

    static String decodeHeaderValue(String value) {
        return value != null ? new String(Base64Url.decode(value), StandardCharsets.UTF_8) : null;
    }

    private static String stringValue(Object value) {
        return value != null ? value.toString() : null;
    }
}
