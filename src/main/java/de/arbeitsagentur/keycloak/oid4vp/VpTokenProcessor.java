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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;

public class VpTokenProcessor {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);

    private final SdJwtVerifier sdJwtVerifier;
    private final ObjectMapper objectMapper;

    public VpTokenProcessor(ObjectMapper objectMapper) {
        this.sdJwtVerifier = new SdJwtVerifier(objectMapper);
        this.objectMapper = objectMapper;
    }

    public Result process(
            String vpToken,
            String clientId,
            String expectedNonce,
            String responseUri,
            boolean trustX5c,
            boolean skipSignatureVerification,
            String alternateResponseUri) {

        try {
            // Detect format: single credential or multi-credential JSON wrapper
            if (vpToken.trim().startsWith("{")) {
                return processMultiCredential(
                        vpToken,
                        clientId,
                        expectedNonce,
                        responseUri,
                        trustX5c,
                        skipSignatureVerification,
                        alternateResponseUri);
            }

            return processSingleCredential(
                    vpToken,
                    clientId,
                    expectedNonce,
                    responseUri,
                    trustX5c,
                    skipSignatureVerification,
                    alternateResponseUri);

        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("VP token processing failed: " + e.getMessage(), e);
        }
    }

    private Result processSingleCredential(
            String vpToken,
            String clientId,
            String expectedNonce,
            String responseUri,
            boolean trustX5c,
            boolean skipSignatureVerification,
            String alternateResponseUri) {

        if (sdJwtVerifier.isSdJwt(vpToken)) {
            SdJwtVerifier.VerificationResult result = verifySdJwtWithFallback(
                    vpToken, clientId, expectedNonce, trustX5c, skipSignatureVerification, alternateResponseUri);

            Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
            credentials.put(
                    "cred1",
                    new VerifiedCredential(
                            "cred1",
                            result.issuer(),
                            result.credentialType(),
                            result.claims(),
                            PresentationType.SD_JWT));

            return new Result(credentials, result.claims());
        }

        // For non-SD-JWT tokens (mDoc will be handled in task 12)
        throw new IdentityBrokerException("Unsupported VP token format");
    }

    @SuppressWarnings("unchecked")
    private Result processMultiCredential(
            String vpToken,
            String clientId,
            String expectedNonce,
            String responseUri,
            boolean trustX5c,
            boolean skipSignatureVerification,
            String alternateResponseUri) {

        try {
            Map<String, Object> wrapper = objectMapper.readValue(vpToken, Map.class);
            Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
            Map<String, Object> mergedClaims = new LinkedHashMap<>();
            int index = 1;

            for (Map.Entry<String, Object> entry : wrapper.entrySet()) {
                String credentialId = entry.getKey();
                Object value = entry.getValue();

                String credential;
                if (value instanceof List<?> list && !list.isEmpty()) {
                    credential = list.get(0).toString();
                } else if (value instanceof String s) {
                    credential = s;
                } else {
                    continue;
                }

                if (sdJwtVerifier.isSdJwt(credential)) {
                    SdJwtVerifier.VerificationResult result = verifySdJwtWithFallback(
                            credential,
                            clientId,
                            expectedNonce,
                            trustX5c,
                            skipSignatureVerification,
                            alternateResponseUri);

                    credentials.put(
                            credentialId,
                            new VerifiedCredential(
                                    credentialId,
                                    result.issuer(),
                                    result.credentialType(),
                                    result.claims(),
                                    PresentationType.SD_JWT));

                    mergedClaims.putAll(result.claims());
                }
            }

            if (credentials.isEmpty()) {
                throw new IdentityBrokerException("No valid credentials found in multi-credential VP token");
            }

            return new Result(credentials, mergedClaims);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to process multi-credential VP token: " + e.getMessage(), e);
        }
    }

    private SdJwtVerifier.VerificationResult verifySdJwtWithFallback(
            String sdJwt,
            String clientId,
            String expectedNonce,
            boolean trustX5c,
            boolean skipSignatureVerification,
            String alternateResponseUri) {
        try {
            return sdJwtVerifier.verify(sdJwt, clientId, expectedNonce, trustX5c, skipSignatureVerification);
        } catch (Exception primaryError) {
            if (alternateResponseUri != null && !alternateResponseUri.isBlank()) {
                try {
                    LOG.debugf(
                            "Primary verification failed, retrying with alternate audience: %s", alternateResponseUri);
                    return sdJwtVerifier.verify(
                            sdJwt, alternateResponseUri, expectedNonce, trustX5c, skipSignatureVerification);
                } catch (Exception fallbackError) {
                    LOG.warnf("Fallback verification also failed: %s", fallbackError.getMessage());
                }
            }
            throw primaryError;
        }
    }

    public enum PresentationType {
        SD_JWT,
        MDOC
    }

    public record VerifiedCredential(
            String credentialId,
            String issuer,
            String credentialType,
            Map<String, Object> claims,
            PresentationType presentationType) {}

    public record Result(Map<String, VerifiedCredential> credentials, Map<String, Object> mergedClaims) {
        public boolean isMultiCredential() {
            return credentials.size() > 1;
        }

        public VerifiedCredential getPrimaryCredential() {
            return credentials.values().stream().findFirst().orElse(null);
        }
    }
}
