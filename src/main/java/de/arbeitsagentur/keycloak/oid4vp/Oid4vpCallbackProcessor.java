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

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider.*;

import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

class Oid4vpCallbackProcessor {

    private static final Logger LOG = Logger.getLogger(Oid4vpCallbackProcessor.class);

    private final Oid4vpIdentityProviderConfig config;
    private final Oid4vpIdentityProvider provider;
    private final Oid4vpResponseDecryptor responseDecryptor;
    private final VpTokenProcessor vpTokenProcessor;

    Oid4vpCallbackProcessor(
            Oid4vpIdentityProviderConfig config,
            Oid4vpIdentityProvider provider,
            Oid4vpResponseDecryptor responseDecryptor,
            VpTokenProcessor vpTokenProcessor) {
        this.config = config;
        this.provider = provider;
        this.responseDecryptor = responseDecryptor;
        this.vpTokenProcessor = vpTokenProcessor;
    }

    BrokeredIdentityContext process(
            AuthenticationSessionModel authSession,
            String state,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription) {

        try {
            return processInternal(authSession, state, vpToken, encryptedResponse, error, errorDescription);
        } catch (Exception e) {
            // Always clean up session notes to prevent stale state on retry
            clearSessionNotes(authSession);
            throw e;
        }
    }

    private BrokeredIdentityContext processInternal(
            AuthenticationSessionModel authSession,
            String state,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription) {

        String expectedState = authSession.getAuthNote(SESSION_STATE);
        if (expectedState == null || !expectedState.equals(state)) {
            throw new IdentityBrokerException("Invalid state parameter");
        }

        if (StringUtil.isNotBlank(error)) {
            String message = StringUtil.isNotBlank(errorDescription) ? error + ": " + errorDescription : error;
            throw new IdentityBrokerException("Wallet returned error: " + message);
        }

        String mdocGeneratedNonce = authSession.getAuthNote(SESSION_MDOC_GENERATED_NONCE);
        if (mdocGeneratedNonce != null) {
            authSession.removeAuthNote(SESSION_MDOC_GENERATED_NONCE);
        }

        if (StringUtil.isBlank(vpToken) && StringUtil.isNotBlank(encryptedResponse)) {
            String encryptionKey = authSession.getAuthNote(SESSION_ENCRYPTION_KEY);
            try {
                vpToken = responseDecryptor.decryptVpToken(encryptedResponse, encryptionKey);
            } catch (Exception e) {
                throw new IdentityBrokerException("Failed to decrypt response: " + e.getMessage(), e);
            }
        }

        if (StringUtil.isBlank(vpToken)) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        LOG.debugf("VP token received (encrypted=%b, length=%d)", encryptedResponse != null, vpToken.length());

        String expectedNonce = authSession.getAuthNote(SESSION_NONCE);
        String responseUri = authSession.getAuthNote(SESSION_RESPONSE_URI);
        String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        String clientId = effectiveClientId != null ? effectiveClientId : authSession.getAuthNote(SESSION_CLIENT_ID);
        String redirectFlowResponseUri = authSession.getAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        boolean trustX5c = config.getEffectiveTrustX5cFromCredential();
        boolean skipSignatureVerification = config.isSkipTrustListVerification();

        VpTokenProcessor.Result vpResult = vpTokenProcessor.process(
                vpToken,
                clientId,
                expectedNonce,
                responseUri,
                trustX5c,
                skipSignatureVerification,
                redirectFlowResponseUri,
                mdocGeneratedNonce);

        VpTokenProcessor.VerifiedCredential primary = vpResult.getPrimaryCredential();
        if (primary == null) {
            throw new IdentityBrokerException("No valid credential found in VP token");
        }

        LOG.debugf(
                "Verified credential: format=%s, type=%s, claims=%s",
                primary.presentationType(),
                primary.credentialType(),
                primary.claims().keySet());

        String issuer = primary.issuer() != null ? primary.issuer() : "unknown";
        String credentialType = primary.credentialType();

        if (!config.isIssuerAllowed(issuer)) {
            throw new IdentityBrokerException("Issuer not allowed: " + issuer);
        }
        if (!config.isCredentialTypeAllowed(credentialType)) {
            throw new IdentityBrokerException("Credential type not allowed: " + credentialType);
        }

        Map<String, Object> claims = vpResult.isMultiCredential() ? vpResult.mergedClaims() : primary.claims();
        String credentialFormat = primary.presentationType() == VpTokenProcessor.PresentationType.MDOC
                ? Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC
                : Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
        String userMappingClaimName = config.getUserMappingClaimForFormat(credentialFormat);
        Object subjectObj = Oid4vpMapperUtils.getNestedValue(claims, userMappingClaimName);
        String subject = subjectObj != null ? subjectObj.toString() : null;

        if (StringUtil.isBlank(subject)) {
            throw new IdentityBrokerException("Missing subject claim '" + userMappingClaimName + "' in credential");
        }

        String identityKey = FederatedIdentityKeyGenerator.generate(issuer, credentialType, subject);

        BrokeredIdentityContext context = new BrokeredIdentityContext(identityKey, config);
        context.setIdp(provider);
        context.setUsername(subject);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
        context.getContextData().put("oid4vp_issuer", issuer);
        context.getContextData().put("oid4vp_subject", subject);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY, credentialType);
        context.getContextData()
                .put(
                        Oid4vpMapperUtils.CONTEXT_PRESENTATION_TYPE_KEY,
                        primary.presentationType().name());

        clearSessionNotes(authSession);
        return context;
    }

    private void clearSessionNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(SESSION_STATE);
        authSession.removeAuthNote(SESSION_NONCE);
        authSession.removeAuthNote(SESSION_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_ENCRYPTION_KEY);
        authSession.removeAuthNote(SESSION_CLIENT_ID);
        authSession.removeAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        authSession.removeAuthNote(SESSION_TAB_ID);
        authSession.removeAuthNote(SESSION_CLIENT_DATA);
        authSession.removeAuthNote(SESSION_CODE);
    }
}
