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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.REQUEST_OBJECT_CONTENT_TYPE;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectEncryptor;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/** Creates request objects and persists the request-scoped state bound to a stable flow handle. */
public class Oid4vpRequestObjectService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectService.class);

    private final KeycloakSession session;
    private final Oid4vpIdentityProvider provider;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpEndpointResponseFactory responseFactory;

    public Oid4vpRequestObjectService(
            KeycloakSession session,
            Oid4vpIdentityProvider provider,
            Oid4vpRequestObjectStore requestObjectStore,
            Oid4vpAuthSessionResolver authSessionResolver,
            Oid4vpEndpointResponseFactory responseFactory) {
        this.session = session;
        this.provider = provider;
        this.requestObjectStore = requestObjectStore;
        this.authSessionResolver = authSessionResolver;
        this.responseFactory = responseFactory;
    }

    public Response generateRequestObject(String requestHandle, String walletNonce, String walletMetadataJson) {
        if (StringUtil.isBlank(requestHandle)) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Missing request handle");
        }

        Oid4vpRequestObjectStore.FlowContextEntry flowContext =
                requestObjectStore.resolveFlowHandle(session, requestHandle);
        if (flowContext == null) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.NOT_FOUND, "not_found", "Request handle not found or expired");
        }

        AuthenticationSessionModel authSession =
                authSessionResolver.resolveFromTokenEntry(flowContext.rootSessionId(), flowContext.tabId());
        if (authSession == null) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST,
                    "session_expired",
                    "Authentication session expired. Please restart the login flow.");
        }

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = null;
        try {
            Oid4vpIdentityProviderConfig config = provider.getConfig();
            Oid4vpResponseMode responseMode = config.getResolvedResponseMode();
            PreparedDcqlQuery preparedDcqlQuery = provider.prepareDcqlQueryFromConfig();
            requestContext = createRequestContext(
                    requestHandle, flowContext, responseMode, preparedDcqlQuery.configuredCredentialTypes());
            requestObjectStore.storeRequestContext(session, requestContext);
            String kid = Oid4vpRequestObjectStore.extractKidFromJwk(requestContext.encryptionKeyJson());
            if (kid != null) {
                requestObjectStore.storeKidIndex(session, kid, requestContext.state());
            }

            SignedRequestObject signedRequest = provider.getRedirectFlowService()
                    .buildSignedRequestObject(new RequestObjectParams(
                            preparedDcqlQuery.dcqlQuery(),
                            config.getVerifierInfo(),
                            requestContext.effectiveClientId(),
                            config.getClientIdScheme(),
                            requestContext.responseUri(),
                            requestContext.state(),
                            requestContext.nonce(),
                            config.getX509CertificatePem(),
                            config.getX509SigningKeyJwk(),
                            requestContext.encryptionKeyJson(),
                            walletNonce,
                            responseMode,
                            config.isUseIdTokenSubject(),
                            config.isEnforceHaip()));

            String responseJwt = maybeEncryptRequestObject(signedRequest.jwt(), walletMetadataJson);
            return Response.ok(responseJwt).type(REQUEST_OBJECT_CONTENT_TYPE).build();
        } catch (IllegalArgumentException e) {
            cleanupRequestContext(requestContext);
            return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", e.getMessage());
        } catch (Exception e) {
            cleanupRequestContext(requestContext);
            LOG.errorf(e, "Failed to generate request object: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private void cleanupRequestContext(Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        if (requestContext == null || StringUtil.isBlank(requestContext.state())) {
            return;
        }
        requestObjectStore.removeRequestContext(session, requestContext.state());
    }

    private String maybeEncryptRequestObject(String responseJwt, String walletMetadataJson) {
        if (StringUtil.isBlank(walletMetadataJson)) {
            return responseJwt;
        }
        try {
            WalletMetadata walletMeta = WalletMetadata.parse(walletMetadataJson);
            return Oid4vpRequestObjectEncryptor.encrypt(responseJwt, walletMeta);
        } catch (Exception e) {
            LOG.warnf("Failed to encrypt request object per wallet_metadata: %s", e.getMessage());
            throw new IllegalArgumentException("Failed to encrypt request object with provided wallet_metadata");
        }
    }

    private Oid4vpRequestObjectStore.RequestContextEntry createRequestContext(
            String requestHandle,
            Oid4vpRequestObjectStore.FlowContextEntry flowContext,
            Oid4vpResponseMode responseMode,
            List<String> configuredCredentialTypes) {
        String state = buildRequestState(flowContext.tabId());
        String nonce = UUID.randomUUID().toString();
        String encryptionKeyJson = null;
        String encryptionJwkThumbprint = null;
        if (responseMode.requiresEncryption()) {
            Oid4vpJwk responseEncryptionKey = provider.getRedirectFlowService().createResponseEncryptionKey();
            encryptionKeyJson = responseEncryptionKey.toJson();
            encryptionJwkThumbprint = Oid4vpRequestObjectStore.computeEncryptionJwkThumbprint(encryptionKeyJson);
        }
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                requestHandle,
                flowContext.rootSessionId(),
                flowContext.tabId(),
                state,
                flowContext.effectiveClientId(),
                flowContext.responseUri(),
                flowContext.flow(),
                nonce,
                encryptionKeyJson,
                encryptionJwkThumbprint,
                configuredCredentialTypes);
    }

    private String buildRequestState(String tabId) {
        if (StringUtil.isBlank(tabId)) {
            return UUID.randomUUID().toString();
        }
        return tabId + "." + UUID.randomUUID();
    }
}
