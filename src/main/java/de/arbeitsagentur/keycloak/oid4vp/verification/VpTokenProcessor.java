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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Top-level processor for VP tokens received from wallets.
 *
 * <p>Handles format detection (SD-JWT vs mDoc), single-credential VP tokens,
 * signature verification (delegated to {@link SdJwtVerifier} / {@link MdocVerifier}),
 * trust list validation, and revocation checking (via {@link StatusListVerifier}).
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7">OID4VP 1.0 §7 — VP Token</a>
 */
public class VpTokenProcessor {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);
    private static final String DEFAULT_CREDENTIAL_ID = "cred1";

    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;
    private final StatusListVerifier statusListVerifier;
    private final ObjectMapper objectMapper;
    private final TrustListProvider trustListProvider;
    private final String expectedTrustListLoTEType;

    public record Config(
            KeycloakSession session,
            String trustListUrl,
            Duration statusListMaxCacheTtl,
            Duration trustListMaxCacheTtl,
            Duration issuerMetadataMaxCacheTtl,
            boolean strictX5cVerification,
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds,
            List<X509Certificate> trustListSigningCerts,
            Duration trustListMaxStaleAge,
            String expectedTrustListLoTEType) {}

    public record Request(
            String vpToken,
            String clientId,
            String expectedNonce,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint) {}

    public VpTokenProcessor(ObjectMapper objectMapper, Config config) {
        this.sdJwtVerifier = new SdJwtVerifier(
                config.clockSkewSeconds(),
                config.kbJwtMaxAgeSeconds(),
                new JwtVcIssuerMetadataResolver(config.session(), config.issuerMetadataMaxCacheTtl()),
                config.strictX5cVerification());
        this.mdocVerifier = new MdocVerifier();
        this.trustListProvider = new TrustListProvider(
                config.session(),
                config.trustListUrl(),
                config.trustListMaxCacheTtl(),
                config.trustListMaxStaleAge(),
                config.trustListSigningCerts());
        this.statusListVerifier =
                new StatusListVerifier(config.session(), this.trustListProvider, config.statusListMaxCacheTtl());
        this.objectMapper = objectMapper;
        this.expectedTrustListLoTEType = config.expectedTrustListLoTEType();
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
        this.expectedTrustListLoTEType = null;
    }

    /**
     * Processes a VP token: detects format, verifies credentials, checks revocation status.
     *
     * @param request the wallet response plus verification context
     */
    public VpTokenResult process(Request request) {
        List<X509Certificate> trustedCerts =
                trustListProvider != null ? trustListProvider.getIssuanceCertificates() : List.of();
        validateTrustListLoTEType();
        LOG.debugf("Trust list provides %d trusted keys", trustedCerts.size());

        try {
            // Detect format: single credential or a JSON wrapper around one credential
            if (request.vpToken().trim().startsWith("{")) {
                return processMultiCredential(
                        request.vpToken(),
                        request.clientId(),
                        request.expectedNonce(),
                        trustedCerts,
                        request.alternateResponseUri(),
                        request.mdocGeneratedNonce(),
                        request.encryptionJwkThumbprint());
            }

            return processSingleCredential(
                    request.vpToken(),
                    request.clientId(),
                    request.expectedNonce(),
                    trustedCerts,
                    request.alternateResponseUri(),
                    request.mdocGeneratedNonce(),
                    request.encryptionJwkThumbprint());

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
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint) {

        VerifiedCredential cred = verifyCredential(
                DEFAULT_CREDENTIAL_ID,
                vpToken,
                clientId,
                expectedNonce,
                trustedCerts,
                alternateResponseUri,
                mdocGeneratedNonce,
                encryptionJwkThumbprint);
        if (cred == null) {
            throw new IdentityBrokerException("Unsupported VP token format");
        }

        return new VpTokenResult(Map.of(DEFAULT_CREDENTIAL_ID, cred), cred.claims());
    }

    @SuppressWarnings("unchecked")
    private VpTokenResult processMultiCredential(
            String vpToken,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint) {

        try {
            Map<String, Object> wrapper = objectMapper.readValue(vpToken, Map.class);
            List<VerifiedCredential> credentials = new ArrayList<>();

            for (Map.Entry<String, Object> entry : wrapper.entrySet()) {
                String credentialId = entry.getKey();
                for (String credential : extractCredentialStrings(entry.getValue())) {
                    VerifiedCredential cred = verifyCredential(
                            credentialId,
                            credential,
                            clientId,
                            expectedNonce,
                            trustedCerts,
                            alternateResponseUri,
                            mdocGeneratedNonce,
                            encryptionJwkThumbprint);
                    if (cred != null) {
                        credentials.add(cred);
                    }
                }
            }

            if (credentials.isEmpty()) {
                throw new IdentityBrokerException("No valid credentials found in multi-credential VP token");
            }

            VerifiedCredential primary = credentials.get(0);
            boolean mixedCredentialTypes = credentials.stream()
                    .skip(1)
                    .map(VerifiedCredential::credentialType)
                    .anyMatch(type -> !Objects.equals(type, primary.credentialType()));
            if (mixedCredentialTypes) {
                throw new IdentityBrokerException("Only one credential type is currently supported in vp_token");
            }

            return new VpTokenResult(Map.of(primary.credentialId(), primary), primary.claims());
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to process multi-credential VP token: " + e.getMessage(), e);
        }
    }

    private List<String> extractCredentialStrings(Object value) {
        if (value instanceof List<?> list && !list.isEmpty()) {
            return list.stream().map(Object::toString).toList();
        }
        if (value instanceof String s) {
            return List.of(s);
        }
        return List.of();
    }

    private VerifiedCredential verifyCredential(
            String credentialId,
            String credential,
            String clientId,
            String expectedNonce,
            List<X509Certificate> trustedCerts,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint) {

        if (sdJwtVerifier.isSdJwt(credential)) {
            SdJwtVerificationResult result =
                    verifySdJwtWithFallback(credential, clientId, expectedNonce, trustedCerts, alternateResponseUri);
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(
                    credentialId, result.issuer(), result.credentialType(), result.claims(), PresentationType.SD_JWT);
        }

        if (mdocVerifier.isMdoc(credential)) {
            // Use alternateResponseUri as the response_uri for session transcript
            byte[] jwkThumbprintBytes = decodeJwkThumbprint(encryptionJwkThumbprint);
            MdocVerificationResult result = mdocVerifier.verifyWithTrustedCerts(
                    credential,
                    trustedCerts,
                    clientId,
                    expectedNonce,
                    alternateResponseUri,
                    mdocGeneratedNonce,
                    jwkThumbprintBytes);
            statusListVerifier.checkRevocationStatus(result.claims());
            return new VerifiedCredential(credentialId, null, result.docType(), result.claims(), PresentationType.MDOC);
        }

        return null;
    }

    private byte[] decodeJwkThumbprint(String encoded) {
        if (StringUtil.isBlank(encoded)) return null;
        try {
            return Base64.getUrlDecoder().decode(encoded);
        } catch (Exception e) {
            LOG.warnf("Failed to decode JWK thumbprint: %s", e.getMessage());
            return null;
        }
    }

    private void validateTrustListLoTEType() {
        if (trustListProvider == null || StringUtil.isBlank(expectedTrustListLoTEType)) {
            return;
        }
        String actualLoTEType = trustListProvider.getCurrentLoTEType();
        if (StringUtil.isBlank(actualLoTEType)) {
            return;
        }
        if (!expectedTrustListLoTEType.equals(actualLoTEType)) {
            throw new IdentityBrokerException("Trust list LoTE type mismatch: expected " + expectedTrustListLoTEType
                    + " but got " + actualLoTEType);
        }
    }

    // Wallets in the field are inconsistent here: some bind the KB-JWT to client_id, others to
    // response_uri. We try the configured client_id first and then one bounded fallback to the
    // redirect flow's response_uri so interoperability does not depend on a single audience choice.
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
