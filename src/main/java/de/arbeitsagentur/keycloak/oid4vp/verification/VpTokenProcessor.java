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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

public class VpTokenProcessor {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);

    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;
    private final StatusListVerifier statusListVerifier;
    private final ObjectMapper objectMapper;
    private final TrustListProvider trustListProvider;

    public VpTokenProcessor(
            ObjectMapper objectMapper,
            KeycloakSession session,
            String trustListUrl,
            Duration statusListMaxCacheTtl,
            Duration trustListMaxCacheTtl,
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds) {
        this.sdJwtVerifier = new SdJwtVerifier(clockSkewSeconds, kbJwtMaxAgeSeconds);
        this.mdocVerifier = new MdocVerifier();
        this.trustListProvider = new TrustListProvider(session, trustListUrl, trustListMaxCacheTtl);
        this.statusListVerifier = new StatusListVerifier(session, this.trustListProvider, statusListMaxCacheTtl);
        this.objectMapper = objectMapper;
    }

    public VpTokenProcessor(ObjectMapper objectMapper, StatusListVerifier statusListVerifier) {
        this(objectMapper, statusListVerifier, null);
    }

    public VpTokenProcessor(
            ObjectMapper objectMapper, StatusListVerifier statusListVerifier, TrustListProvider trustListProvider) {
        this.sdJwtVerifier = new SdJwtVerifier(
                Oid4vpIdentityProviderConfig.DEFAULT_CLOCK_SKEW_SECONDS,
                Oid4vpIdentityProviderConfig.DEFAULT_KB_JWT_MAX_AGE_SECONDS);
        this.mdocVerifier = new MdocVerifier();
        this.statusListVerifier = statusListVerifier;
        this.trustListProvider = trustListProvider;
        this.objectMapper = objectMapper;
    }

    public VpTokenResult process(String vpToken, String clientId, String expectedNonce, String alternateResponseUri) {

        LOG.tracef("Processing VP token (length=%d): %s", vpToken.length(), vpToken);

        List<X509Certificate> trustedCerts =
                trustListProvider != null ? trustListProvider.getTrustedCertificates() : List.of();
        LOG.debugf("Trust list provides %d trusted keys", trustedCerts.size());

        try {
            // Detect format: single credential or multi-credential JSON wrapper
            if (vpToken.trim().startsWith("{")) {
                return processMultiCredential(vpToken, clientId, expectedNonce, trustedCerts, alternateResponseUri);
            }

            return processSingleCredential(vpToken, clientId, expectedNonce, trustedCerts, alternateResponseUri);

        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("VP token processing failed: " + e.getMessage(), e);
        }
    }

    private VpTokenResult processSingleCredential(
            String vpToken,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri) {

        VerifiedCredential cred =
                verifyCredential("cred1", vpToken, clientId, expectedNonce, trustedCerts, alternateResponseUri);
        if (cred == null) {
            throw new IdentityBrokerException("Unsupported VP token format");
        }

        return new VpTokenResult(Map.of("cred1", cred), cred.claims());
    }

    @SuppressWarnings("unchecked")
    private VpTokenResult processMultiCredential(
            String vpToken,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri) {

        try {
            Map<String, Object> wrapper = objectMapper.readValue(vpToken, Map.class);
            Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
            Map<String, Object> mergedClaims = new LinkedHashMap<>();

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

                VerifiedCredential cred = verifyCredential(
                        credentialId, credential, clientId, expectedNonce, trustedCerts, alternateResponseUri);
                if (cred != null) {
                    credentials.put(credentialId, cred);
                    mergedClaims.putAll(cred.claims());
                }
            }

            if (credentials.isEmpty()) {
                throw new IdentityBrokerException("No valid credentials found in multi-credential VP token");
            }

            return new VpTokenResult(credentials, mergedClaims);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to process multi-credential VP token: " + e.getMessage(), e);
        }
    }

    private VerifiedCredential verifyCredential(
            String credentialId,
            String credential,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri) {

        if (sdJwtVerifier.isSdJwt(credential)) {
            SdJwtVerificationResult result =
                    verifySdJwtWithFallback(credential, clientId, expectedNonce, trustedCerts, alternateResponseUri);
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(
                    credentialId, result.issuer(), result.credentialType(), result.claims(), PresentationType.SD_JWT);
        }

        if (mdocVerifier.isMdoc(credential)) {
            MdocVerificationResult result = mdocVerifier.verifyWithTrustedCerts(credential, trustedCerts);
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(credentialId, null, result.docType(), result.claims(), PresentationType.MDOC);
        }

        return null;
    }

    // Wallets may set the KB-JWT "aud" claim to either client_id or response_uri depending on the flow.
    // Try client_id first, then fall back to alternateResponseUri (the redirect flow's response_uri).
    private SdJwtVerificationResult verifySdJwtWithFallback(
            String sdJwt,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri) {
        try {
            return sdJwtVerifier.verify(sdJwt, clientId, expectedNonce, trustedCerts);
        } catch (Exception primaryError) {
            if (StringUtil.isNotBlank(alternateResponseUri)) {
                try {
                    LOG.debugf(
                            "Primary verification failed, retrying with alternate audience: %s", alternateResponseUri);
                    return sdJwtVerifier.verify(sdJwt, alternateResponseUri, expectedNonce, trustedCerts);
                } catch (Exception fallbackError) {
                    LOG.warnf("Fallback verification also failed: %s", fallbackError.getMessage());
                }
            }
            throw primaryError;
        }
    }
}
