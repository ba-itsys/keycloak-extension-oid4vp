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
package de.arbeitsagentur.keycloak.oid4vp;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import java.util.Map;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class Oid4vpResponseDecryptor {

    public record DecryptedResponse(String vpToken, String mdocGeneratedNonce, String error, String errorDescription) {}

    public String decryptVpToken(String encryptedResponse, String encryptionKeyJson) {
        if (StringUtil.isBlank(encryptionKeyJson)) {
            throw new IllegalStateException("No encryption key available for decryption");
        }
        try {
            ECKey decryptionKey = ECKey.parse(encryptionKeyJson);
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            jwe.decrypt(new ECDHDecrypter(decryptionKey));
            String payload = jwe.getPayload().toString();

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            if (payloadMap.containsKey("error")) {
                String err = payloadMap.get("error").toString();
                String desc = payloadMap.containsKey("error_description")
                        ? payloadMap.get("error_description").toString()
                        : "";
                throw new IdentityBrokerException("Wallet error: " + err + (desc.isEmpty() ? "" : " - " + desc));
            }

            if (!payloadMap.containsKey("vp_token")) {
                throw new IdentityBrokerException("Missing vp_token in encrypted response");
            }

            Object vpTokenObj = payloadMap.get("vp_token");
            return vpTokenObj instanceof String
                    ? (String) vpTokenObj
                    : JsonSerialization.writeValueAsString(vpTokenObj);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt response: " + e.getMessage(), e);
        }
    }

    public DecryptedResponse decryptFull(String encryptedResponse, String encryptionKeyJson) {
        if (StringUtil.isBlank(encryptionKeyJson)) {
            throw new IllegalStateException("No encryption key available for decryption");
        }
        try {
            ECKey decryptionKey = ECKey.parse(encryptionKeyJson);
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            jwe.decrypt(new ECDHDecrypter(decryptionKey));
            String payload = jwe.getPayload().toString();

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            String mdocGeneratedNonce = null;
            com.nimbusds.jose.util.Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
            if (apu != null) {
                mdocGeneratedNonce = apu.toString();
            }

            if (payloadMap.containsKey("error")) {
                return new DecryptedResponse(
                        null,
                        mdocGeneratedNonce,
                        payloadMap.get("error").toString(),
                        payloadMap.containsKey("error_description")
                                ? payloadMap.get("error_description").toString()
                                : null);
            }

            String vpToken = null;
            if (payloadMap.containsKey("vp_token")) {
                Object vpTokenObj = payloadMap.get("vp_token");
                vpToken = vpTokenObj instanceof String
                        ? (String) vpTokenObj
                        : JsonSerialization.writeValueAsString(vpTokenObj);
            }

            return new DecryptedResponse(vpToken, mdocGeneratedNonce, null, null);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt response: " + e.getMessage(), e);
        }
    }
}
