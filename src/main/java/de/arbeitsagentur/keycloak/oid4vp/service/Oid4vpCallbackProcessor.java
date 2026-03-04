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
import de.arbeitsagentur.keycloak.oid4vp.verification.SelfIssuedIdTokenValidator;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.sessions.AuthenticationSessionModel;
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

    /**
     * Validates the VP token (and optionally a Self-Issued ID Token) and builds a brokered
     * identity context for Keycloak's identity broker.
     * Clears session notes on both success and failure to prevent stale state on retry.
     */
    public BrokeredIdentityContext process(
            AuthenticationSessionModel authSession, String state, String vpToken, String idToken) {

        try {
            return processInternal(authSession, state, vpToken, idToken);
        } catch (Exception e) {
            // Always clean up session notes to prevent stale state on retry
            clearSessionNotes(authSession);
            throw e;
        }
    }

    private BrokeredIdentityContext processInternal(
            AuthenticationSessionModel authSession, String state, String vpToken, String idToken) {

        String expectedState = authSession.getAuthNote(SESSION_STATE);
        if (expectedState == null || !expectedState.equals(state)) {
            throw new IdentityBrokerException("Invalid state parameter");
        }

        if (StringUtil.isBlank(vpToken)) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        LOG.debugf("VP token received (length=%d)", vpToken.length());

        String expectedNonce = authSession.getAuthNote(SESSION_NONCE);
        String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        String clientId = effectiveClientId != null ? effectiveClientId : authSession.getAuthNote(SESSION_CLIENT_ID);
        String redirectFlowResponseUri = authSession.getAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        String mdocGeneratedNonce = authSession.getAuthNote(SESSION_MDOC_GENERATED_NONCE);
        String encryptionJwkThumbprint = authSession.getAuthNote(SESSION_ENCRYPTION_JWK_THUMBPRINT);

        VpTokenResult vpResult = vpTokenProcessor.process(
                vpToken, clientId, expectedNonce, redirectFlowResponseUri, mdocGeneratedNonce, encryptionJwkThumbprint);

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
        if (!configProvider.isCredentialTypeAllowed(credentialType)) {
            throw new IdentityBrokerException("Credential type not allowed: " + credentialType);
        }

        Map<String, Object> claims = Oid4vpMapperUtils.toMutableClaims(
                vpResult.isMultiCredential() ? vpResult.mergedClaims() : primary.claims());

        String subject;
        if (configProvider.isUseIdTokenSubject()) {
            subject = validateIdTokenAndExtractSubject(idToken, clientId, expectedNonce);
        } else {
            subject = extractSubjectFromCredential(claims, primary);
        }

        String identityKey = primary.generateIdentityKey(subject);

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

        clearSessionNotes(authSession);
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

    private void clearSessionNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(SESSION_STATE);
        authSession.removeAuthNote(SESSION_NONCE);
        authSession.removeAuthNote(SESSION_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_CLIENT_ID);
        authSession.removeAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        authSession.removeAuthNote(SESSION_MDOC_GENERATED_NONCE);
        authSession.removeAuthNote(SESSION_ENCRYPTION_JWK_THUMBPRINT);
    }
}
