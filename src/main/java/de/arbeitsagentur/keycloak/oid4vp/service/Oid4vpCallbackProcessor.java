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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.SelfIssuedIdTokenValidator;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.utils.StringUtil;

/**
 * Processes verified VP token responses into Keycloak {@link BrokeredIdentityContext} objects.
 *
 * <p>Orchestrates the post-response phase of the OID4VP flow: validates the state parameter,
 * delegates VP token verification to {@link VpTokenProcessor}, enforces issuer/credential type
 * allow-lists, resolves the user identity from the configured mapping claim (or from a SIOPv2
 * Self-Issued ID Token when {@code useIdTokenSubject} is enabled), and populates the brokered
 * identity context with credential claims for downstream mappers.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7">OID4VP 1.0 §7 — VP Token Validation</a>
 */
public class Oid4vpCallbackProcessor {

    private static final Logger LOG = Logger.getLogger(Oid4vpCallbackProcessor.class);

    private final IdentityProviderModel idpModel;
    private final Oid4vpConfigProvider configProvider;
    private final UserAuthenticationIdentityProvider<?> provider;
    private final VpTokenProcessor vpTokenProcessor;

    public Oid4vpCallbackProcessor(
            IdentityProviderModel idpModel,
            Oid4vpConfigProvider configProvider,
            UserAuthenticationIdentityProvider<?> provider,
            VpTokenProcessor vpTokenProcessor) {
        this.idpModel = idpModel;
        this.configProvider = configProvider;
        this.provider = provider;
        this.vpTokenProcessor = vpTokenProcessor;
    }

    /** Validates the VP token (and optionally a Self-Issued ID Token) and builds a brokered identity context. */
    public BrokeredIdentityContext process(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext,
            String vpToken,
            String idToken,
            String mdocGeneratedNonce) {

        if (requestContext == null || StringUtil.isBlank(requestContext.state())) {
            throw new IdentityBrokerException("Missing request context");
        }

        if (StringUtil.isBlank(vpToken)) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        LOG.debugf("VP token received (length=%d)", vpToken.length());

        VpTokenResult vpResult = vpTokenProcessor.process(
                vpToken,
                requestContext.effectiveClientId(),
                requestContext.nonce(),
                requestContext.responseUri(),
                mdocGeneratedNonce,
                requestContext.encryptionJwkThumbprint());

        VerifiedCredential primary = vpResult.getPrimaryCredential();
        if (primary == null) {
            throw new IdentityBrokerException("No valid credential found in VP token");
        }

        LOG.debugf(
                "Verified credential: format=%s, type=%s, claims=%s",
                primary.presentationType(),
                primary.credentialType(),
                primary.claims().keySet());

        String issuer = primary.issuer();
        String credentialType = primary.credentialType();

        if (issuer != null && !configProvider.isIssuerAllowed(issuer)) {
            throw new IdentityBrokerException("Issuer not allowed: " + issuer);
        }
        enforceConfiguredCredentialTypes(requestContext, vpResult);

        Map<String, Object> claims = Oid4vpMapperUtils.toMutableClaims(
                vpResult.isMultiCredential() ? vpResult.mergedClaims() : primary.claims());

        String subject;
        String identityKey;
        if (configProvider.isTransientUsersEnabled()) {
            subject = buildTransientSubject(requestContext);
            identityKey = primary.generateIdentityKey(subject);
        } else if (configProvider.isUseIdTokenSubject()) {
            subject = validateIdTokenAndExtractSubject(
                    idToken, requestContext.effectiveClientId(), requestContext.nonce());
            identityKey = primary.generateIdentityKey(subject);
        } else {
            subject = extractSubjectFromCredential(claims, primary);
            identityKey = primary.generateCaseInsensitiveIdentityKey(subject);
        }

        BrokeredIdentityContext context = new BrokeredIdentityContext(identityKey, idpModel);
        context.setIdp(provider);
        context.setUsername(subject);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
        if (issuer != null) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY, issuer);
        }
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY, subject);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY, credentialType);
        context.getContextData()
                .put(
                        Oid4vpMapperUtils.CONTEXT_PRESENTATION_TYPE_KEY,
                        primary.presentationType().name());
        return context;
    }

    private String validateIdTokenAndExtractSubject(String idToken, String clientId, String expectedNonce) {
        if (StringUtil.isBlank(idToken)) {
            throw new IdentityBrokerException("ID token subject mode enabled but no id_token received");
        }
        try {
            SelfIssuedIdTokenValidator validator = new SelfIssuedIdTokenValidator(configProvider.getClockSkewSeconds());
            String subject = validator.validate(idToken, clientId, expectedNonce);
            LOG.debugf("ID token validated, subject (JWK Thumbprint): %s", subject);
            return subject;
        } catch (IllegalArgumentException e) {
            throw new IdentityBrokerException("ID token validation failed: " + e.getMessage(), e);
        }
    }

    private String extractSubjectFromCredential(Map<String, Object> claims, VerifiedCredential primary) {
        String credentialFormat =
                primary.presentationType() == PresentationType.MDOC ? FORMAT_MSO_MDOC : FORMAT_SD_JWT_VC;
        String userMappingClaimName = configProvider.getUserMappingClaimForFormat(credentialFormat);
        Object subjectObj = Oid4vpMapperUtils.getNestedValue(claims, userMappingClaimName);
        String subject = Oid4vpMapperUtils.toStringValue(subjectObj);

        if (StringUtil.isBlank(subject)) {
            throw new IdentityBrokerException("Missing subject claim '" + userMappingClaimName + "' in credential");
        }
        return subject;
    }

    private String buildTransientSubject(Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        String requestHandle = requestContext != null && StringUtil.isNotBlank(requestContext.requestHandle())
                ? requestContext.requestHandle()
                : "unknown";
        LOG.debugf(
                "OID4VP IdP '%s': generating transient subject for request handle '%s'",
                idpModel.getAlias(), requestHandle);
        return "transient-" + requestHandle + "-" + UUID.randomUUID();
    }

    private void enforceConfiguredCredentialTypes(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, VpTokenResult vpResult) {
        Set<String> configuredCredentialTypes = new LinkedHashSet<>(
                requestContext != null && requestContext.configuredCredentialTypes() != null
                        ? requestContext.configuredCredentialTypes()
                        : List.of());
        if (configuredCredentialTypes.isEmpty()) {
            return;
        }
        for (VerifiedCredential credential : vpResult.credentials().values()) {
            String credentialType = credential.credentialType();
            if (credentialType == null || !configuredCredentialTypes.contains(credentialType)) {
                throw new IdentityBrokerException("Credential type not trusted by this OID4VP IdP: " + credentialType);
            }
        }
    }
}
