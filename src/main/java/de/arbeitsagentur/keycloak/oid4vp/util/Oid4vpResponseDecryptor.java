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

public class Oid4vpResponseDecryptor {

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseDecryptor.class);

    public String extractKid(String encryptedResponse) {
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            return jwe.getHeader().getKeyID();
        } catch (Exception e) {
            LOG.warnf("Failed to extract KID from JWE: %s", e.getMessage());
            return null;
        }
    }

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
                mdocGeneratedNonce = apu.toString();
            }

            if (payloadMap.containsKey(OAuth2Constants.ERROR)) {
                return new DecryptedResponse(
                        null,
                        mdocGeneratedNonce,
                        payloadMap.get(OAuth2Constants.ERROR).toString(),
                        payloadMap.containsKey(OAuth2Constants.ERROR_DESCRIPTION)
                                ? payloadMap
                                        .get(OAuth2Constants.ERROR_DESCRIPTION)
                                        .toString()
                                : null);
            }

            String vpToken = null;
            if (payloadMap.containsKey(VP_TOKEN)) {
                Object vpTokenObj = payloadMap.get(VP_TOKEN);
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
