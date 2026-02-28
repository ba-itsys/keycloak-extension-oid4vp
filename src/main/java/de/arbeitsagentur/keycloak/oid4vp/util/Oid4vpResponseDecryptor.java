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

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreDecryptionResult;
import de.arbeitsagentur.keycloak.oid4vp.domain.StoredRequestObject;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class Oid4vpResponseDecryptor {

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseDecryptor.class);

    public PreDecryptionResult tryPreDecrypt(
            String encryptedResponse, Oid4vpRequestObjectStore requestObjectStore, KeycloakSession session) {
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            String kid = jwe.getHeader().getKeyID();
            if (kid == null) {
                return PreDecryptionResult.EMPTY;
            }

            StoredRequestObject stored = requestObjectStore.resolveByKid(session, kid);
            if (stored == null || stored.encryptionKeyJson() == null) {
                return PreDecryptionResult.EMPTY;
            }

            ECKey decryptionKey = ECKey.parse(stored.encryptionKeyJson());
            jwe.decrypt(new ECDHDecrypter(decryptionKey));
            String payload = jwe.getPayload().toString();

            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = JsonSerialization.readValue(payload, Map.class);

            String mdocGeneratedNonce = null;
            Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
            if (apu != null) {
                mdocGeneratedNonce = apu.toString();
            }

            if (payloadMap.containsKey("error")) {
                return new PreDecryptionResult(
                        stored.state(),
                        null,
                        payloadMap.get("error").toString(),
                        payloadMap.containsKey("error_description")
                                ? payloadMap.get("error_description").toString()
                                : null,
                        mdocGeneratedNonce);
            }

            String vpToken = null;
            if (payloadMap.containsKey("vp_token")) {
                Object vpTokenObj = payloadMap.get("vp_token");
                vpToken = vpTokenObj instanceof String
                        ? (String) vpTokenObj
                        : JsonSerialization.writeValueAsString(vpTokenObj);
            }

            return new PreDecryptionResult(stored.state(), vpToken, null, null, mdocGeneratedNonce);
        } catch (Exception e) {
            LOG.warnf("JWE kid lookup/decrypt failed: %s", e.getMessage());
            return PreDecryptionResult.EMPTY;
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
            Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
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
