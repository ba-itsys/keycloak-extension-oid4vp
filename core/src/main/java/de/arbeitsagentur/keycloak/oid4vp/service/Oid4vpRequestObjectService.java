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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectEncryptor;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

// Signs request objects on demand from the request context allocated at login-page render.
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

    public Response generateRequestObject(String state, String walletNonce, String walletMetadataJson) {
        if (StringUtil.isBlank(state)) {
            return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state");
        }

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestObjectStore.resolveByState(session, state);
        if (requestContext == null) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.NOT_FOUND, "not_found", "State not found or expired");
        }

        AuthenticationSessionModel authSession =
                authSessionResolver.resolveFromTokenEntry(requestContext.rootSessionId(), requestContext.tabId());
        if (authSession == null) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST,
                    "session_expired",
                    "Authentication session expired. Please restart the login flow.");
        }

        try {
            Oid4vpIdentityProviderConfig config = provider.getConfig();
            Oid4vpResponseMode responseMode = config.getResolvedResponseMode();
            PreparedDcqlQuery preparedDcqlQuery = provider.prepareDcqlQueryFromConfig();

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
            return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", e.getMessage());
        } catch (Exception e) {
            LOG.errorf(e, "Failed to generate request object: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
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
}
