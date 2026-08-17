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
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.trust.CredentialTrustPlan;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Top-level processor for VP tokens received from wallets.
 *
 * <p>Handles format detection (SD-JWT vs mDoc), single-credential VP tokens,
 * signature verification (delegated to {@link SdJwtVerifier} / {@link MdocVerifier}),
 * trust validation, and revocation checking (via {@link StatusListVerifier}).
 *
 * <p>Trust is selected per credential: a presentation is verified against the trust material of the
 * providers serving the credential type that was requested under the credential id the wallet
 * answered with. The requested id to credential type binding comes from the request context, never
 * from the presentation, so a wallet cannot choose the trust domain its credential is judged by.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7">OID4VP 1.0 §7 — VP Token</a>
 */
public class VpTokenProcessor implements VpTokenVerifier {

    private static final Logger LOG = Logger.getLogger(VpTokenProcessor.class);
    /** Placeholder id of a bare credential that cannot be attributed to a requested one. */
    private static final String UNATTRIBUTED_CREDENTIAL_ID = "cred1";

    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;
    private final StatusListVerifier statusListVerifier;
    private final ObjectMapper objectMapper;
    private final Supplier<CredentialTrustPlan> trustPlanSupplier;

    public record Config(
            KeycloakSession session,
            Supplier<CredentialTrustPlan> trustPlanSupplier,
            Duration statusListMaxCacheTtl,
            Duration issuerMetadataMaxCacheTtl,
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds) {}

    public record Request(
            String vpToken,
            String clientId,
            String expectedNonce,
            String alternateResponseUri,
            String mdocGeneratedNonce,
            String encryptionJwkThumbprint,
            List<RequestedCredential> requestedCredentials) {

        public Request {
            requestedCredentials = requestedCredentials != null ? List.copyOf(requestedCredentials) : List.of();
        }
    }

    public VpTokenProcessor(ObjectMapper objectMapper, Config config) {
        this.sdJwtVerifier = new SdJwtVerifier(
                config.clockSkewSeconds(),
                config.kbJwtMaxAgeSeconds(),
                new JwtVcIssuerMetadataResolver(config.session(), config.issuerMetadataMaxCacheTtl()));
        this.mdocVerifier = new MdocVerifier(config.clockSkewSeconds());
        this.trustPlanSupplier = config.trustPlanSupplier();
        this.statusListVerifier = new StatusListVerifier(config.session(), config.statusListMaxCacheTtl());
        this.objectMapper = objectMapper;
    }

    public VpTokenProcessor(ObjectMapper objectMapper, StatusListVerifier statusListVerifier) {
        this(objectMapper, statusListVerifier, null);
    }

    public VpTokenProcessor(
            ObjectMapper objectMapper,
            StatusListVerifier statusListVerifier,
            Supplier<CredentialTrustPlan> trustPlanSupplier) {
        this.sdJwtVerifier = new SdJwtVerifier(
                Oid4vpIdentityProviderConfig.DEFAULT_CLOCK_SKEW_SECONDS,
                Oid4vpIdentityProviderConfig.DEFAULT_KB_JWT_MAX_AGE_SECONDS);
        this.mdocVerifier = new MdocVerifier(Oid4vpIdentityProviderConfig.DEFAULT_CLOCK_SKEW_SECONDS);
        this.statusListVerifier = statusListVerifier;
        this.trustPlanSupplier = trustPlanSupplier;
        this.objectMapper = objectMapper;
    }

    private CredentialTrustPlan resolveTrustPlan() {
        CredentialTrustPlan plan = trustPlanSupplier != null ? trustPlanSupplier.get() : null;
        return plan != null ? plan : CredentialTrustPlan.empty();
    }

    @Override
    public VpTokenResult process(Request request) {
        CredentialTrustSelection trust =
                new CredentialTrustSelection(resolveTrustPlan(), request.requestedCredentials());

        try {
            // Detect format: single credential or a JSON wrapper around one credential
            if (request.vpToken().trim().startsWith("{")) {
                return processMultiCredential(request, trust);
            }

            return processSingleCredential(request, trust);

        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("VP token processing failed: " + e.getMessage(), e);
        }
    }

    private VpTokenResult processSingleCredential(Request request, CredentialTrustSelection trust) {
        String credentialId = trust.singleCredentialId();
        VerifiedCredential cred = verifyCredential(credentialId, request.vpToken(), request, trust);
        if (cred == null) {
            throw new IdentityBrokerException("Unsupported VP token format");
        }

        return new VpTokenResult(Map.of(credentialId, cred), cred.claims());
    }

    @SuppressWarnings("unchecked")
    private VpTokenResult processMultiCredential(Request request, CredentialTrustSelection trust) {
        try {
            Map<String, Object> wrapper = objectMapper.readValue(request.vpToken(), Map.class);
            Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();

            for (Map.Entry<String, Object> entry : wrapper.entrySet()) {
                String credentialId = entry.getKey();
                for (String credential : extractCredentialStrings(entry.getValue())) {
                    VerifiedCredential cred = verifyCredential(credentialId, credential, request, trust);
                    // Several presentations under one id answer the same request: the first one is
                    // used, and an invalid duplicate aborts the login during its own verification.
                    if (cred != null) {
                        credentials.putIfAbsent(credentialId, cred);
                    }
                }
            }

            if (credentials.isEmpty()) {
                throw new IdentityBrokerException("No valid credentials found in multi-credential VP token");
            }

            Map<String, Object> mergedClaims = new LinkedHashMap<>();
            credentials.values().forEach(credential -> mergedClaims.putAll(credential.claims()));
            return new VpTokenResult(credentials, mergedClaims);
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
            String credentialId, String credential, Request request, CredentialTrustSelection trustSelection) {

        ResolvedTrust trust = trustSelection.forCredentialId(credentialId);
        LOG.debugf(
                "Credential '%s' is verified against %d trust anchor sets, %d direct issuer certificates and %d issuer keys",
                credentialId,
                trust.issuanceTrust().size(),
                trust.directIssuerCertificates().size(),
                trust.trustedIssuerKeys().size());

        if (sdJwtVerifier.isSdJwt(credential)) {
            SdJwtVerificationResult result = verifySdJwtWithFallback(
                    credential, request.clientId(), request.expectedNonce(), trust, request.alternateResponseUri());
            statusListVerifier.checkRevocationStatus(result.claims(), trust.revocationCertificates());
            return new VerifiedCredential(
                    credentialId, result.issuer(), result.credentialType(), result.claims(), PresentationType.SD_JWT);
        }

        if (mdocVerifier.isMdoc(credential)) {
            byte[] jwkThumbprintBytes = decodeJwkThumbprint(request.encryptionJwkThumbprint());
            MdocVerificationResult result = mdocVerifier.verifyPresentation(
                    credential,
                    trust,
                    request.clientId(),
                    request.expectedNonce(),
                    request.alternateResponseUri(),
                    request.mdocGeneratedNonce(),
                    jwkThumbprintBytes);
            statusListVerifier.checkRevocationStatus(result.claims(), trust.revocationCertificates());
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

    // Wallets in the field are inconsistent here: some bind the KB-JWT to client_id, others to
    // response_uri. We try the configured client_id first and then one bounded fallback to the
    // redirect flow's response_uri so interoperability does not depend on a single audience choice.
    private SdJwtVerificationResult verifySdJwtWithFallback(
            String sdJwt, String clientId, String expectedNonce, ResolvedTrust trust, String alternateResponseUri) {
        try {
            return sdJwtVerifier.verify(sdJwt, clientId, expectedNonce, trust);
        } catch (Exception primaryError) {
            if (StringUtil.isNotBlank(alternateResponseUri)) {
                try {
                    LOG.debugf(
                            "Primary verification failed, retrying with alternate audience: %s", alternateResponseUri);
                    return sdJwtVerifier.verify(sdJwt, alternateResponseUri, expectedNonce, trust);
                } catch (Exception fallbackError) {
                    LOG.warnf("Fallback verification also failed: %s", fallbackError.getMessage());
                }
            }
            throw primaryError;
        }
    }

    /**
     * Resolves the trust material of one response, keyed by the credential id the wallet answered
     * under. An id that was not requested is rejected before any signature is verified, so an
     * unknown id can never borrow the trust of a requested credential.
     */
    private static class CredentialTrustSelection {

        private final CredentialTrustPlan trustPlan;
        private final Map<String, String> credentialTypeById;

        CredentialTrustSelection(CredentialTrustPlan trustPlan, List<RequestedCredential> requestedCredentials) {
            this.trustPlan = trustPlan;
            Map<String, String> credentialTypeById = new LinkedHashMap<>();
            requestedCredentials.forEach(requested -> credentialTypeById.put(requested.id(), requested.type()));
            this.credentialTypeById = Map.copyOf(credentialTypeById);
        }

        ResolvedTrust forCredentialId(String credentialId) {
            if (credentialTypeById.isEmpty()) {
                // A request that carries no DCQL query binds no id to a type, so only the providers
                // serving every credential type can judge the response.
                return trustPlan.forCredentialType(null);
            }
            String credentialType = credentialTypeById.get(credentialId);
            if (credentialType == null) {
                throw new IdentityBrokerException(
                        "VP token contains the credential id '" + credentialId + "', which was not requested");
            }
            return trustPlan.forCredentialType(credentialType);
        }

        /**
         * The credential id of a VP token that is a bare credential instead of the credential id
         * keyed object OID4VP 1.0 §8.1 defines. It can only be attributed when exactly one
         * credential was requested; otherwise the placeholder id is not among the requested ids
         * and the presentation is rejected.
         */
        String singleCredentialId() {
            if (credentialTypeById.size() == 1) {
                return credentialTypeById.keySet().iterator().next();
            }
            if (credentialTypeById.size() > 1) {
                LOG.warnf(
                        "VP token is a bare credential, but %d credentials were requested, so it cannot be attributed "
                                + "to a credential id and is rejected.",
                        credentialTypeById.size());
            }
            return UNATTRIBUTED_CREDENTIAL_ID;
        }
    }
}
