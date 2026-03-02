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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;

import com.nimbusds.jose.jwk.ECKey;
import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCrossDeviceSseService;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpResponseDecryptor;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

@Vetoed
@Path("")
public class Oid4vpIdentityProviderEndpoint {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderEndpoint.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpIdentityProvider provider;
    private final AbstractIdentityProvider.AuthenticationCallback callback;
    private final EventBuilder event;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpResponseDecryptor responseDecryptor;
    private final Oid4vpDirectPostService directPostService;
    private final Oid4vpCrossDeviceSseService sseService;

    public Oid4vpIdentityProviderEndpoint(
            KeycloakSession session,
            RealmModel realm,
            Oid4vpIdentityProvider provider,
            AbstractIdentityProvider.AuthenticationCallback callback,
            EventBuilder event,
            Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.provider = provider;
        this.callback = callback;
        this.event = event;
        this.requestObjectStore = requestObjectStore;
        this.authSessionResolver = new Oid4vpAuthSessionResolver(session, realm, requestObjectStore);
        this.responseDecryptor = new Oid4vpResponseDecryptor();
        this.directPostService = new Oid4vpDirectPostService(
                session, realm, provider.getConfig(), authSessionResolver, requestObjectStore);
        this.sseService = new Oid4vpCrossDeviceSseService(session, realm, provider.getConfig());
    }

    private IdentityProviderModel getIdpModel() {
        return provider.getConfig();
    }

    @GET
    public Response handleGet(
            @QueryParam(OAuth2Constants.STATE) String state,
            @QueryParam(OAuth2Constants.ERROR) String error,
            @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null && state != null) {
            authSession = authSessionResolver.resolveFromStore(state, null);
        }

        if (StringUtil.isNotBlank(error)) {
            if (authSession != null) {
                return handleError(error, errorDescription, false);
            }
            event.event(EventType.LOGIN_ERROR)
                    .detail(OAuth2Constants.ERROR, error)
                    .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                    .error(Errors.IDENTITY_PROVIDER_ERROR);
            return callback.error(getIdpModel(), error + (errorDescription != null ? ": " + errorDescription : ""));
        }

        return callback.error(getIdpModel(), "No credential response received");
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response handlePost(
            @QueryParam(OAuth2Constants.STATE) String queryState,
            @QueryParam(PARAM_TAB_ID) String tabId,
            @QueryParam(FLOW_PARAM) String flow,
            @FormParam(OAuth2Constants.STATE) String formState,
            @FormParam(VP_TOKEN) String vpToken,
            @FormParam(RESPONSE) String encryptedResponse,
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        try {
            return handlePostInternal(
                    queryState, tabId, flow, formState, vpToken, encryptedResponse, error, errorDescription);
        } catch (Exception e) {
            LOG.errorf(e, "Uncaught exception in handlePost: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", e.getMessage());
        }
    }

    private Response handlePostInternal(
            String queryState,
            String tabId,
            String flow,
            String formState,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription) {

        boolean isCrossDeviceFlow = FLOW_CROSS_DEVICE.equals(flow);
        String state = StringUtil.isNotBlank(queryState) ? queryState : formState;

        // Resolve state + decryption key from KID when state is absent (direct_post.jwt flow)
        ECKey kidBasedKey = null;
        if (StringUtil.isBlank(state) && StringUtil.isNotBlank(encryptedResponse)) {
            ResolvedKid resolved = resolveFromKid(encryptedResponse);
            if (resolved != null) {
                kidBasedKey = resolved.key();
                state = resolved.state();
            }
        }

        // Resolve auth session
        boolean isDirectPostFlow = isCrossDeviceFlow;
        AuthenticationSessionModel authSession = authSessionResolver.resolve(state, tabId, callback);
        if (authSession == null && state != null) {
            authSession = authSessionResolver.resolveFromStore(state, null);
            if (authSession != null) {
                isDirectPostFlow = true;
            }
        }

        if (authSession == null) {
            event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "session_expired", null);
        }

        // Decrypt if encrypted
        boolean wasEncrypted = false;
        if (StringUtil.isNotBlank(encryptedResponse)) {
            if (kidBasedKey != null) {
                DecryptedResponse decrypted = responseDecryptor.decrypt(encryptedResponse, kidBasedKey);
                wasEncrypted = true;
                vpToken = decrypted.vpToken() != null ? decrypted.vpToken() : vpToken;
                error = decrypted.error() != null ? decrypted.error() : error;
                errorDescription = decrypted.error() != null ? decrypted.errorDescription() : errorDescription;
                if (decrypted.mdocGeneratedNonce() != null) {
                    authSession.setAuthNote(SESSION_MDOC_GENERATED_NONCE, decrypted.mdocGeneratedNonce());
                }
            }
        }

        if (isDirectPostFlow) {
            String actualResponseUri = UriBuilder.fromUri(
                            session.getContext().getUri().getRequestUri())
                    .replaceQueryParam(OAuth2Constants.STATE)
                    .build()
                    .toString();
            authSession.setAuthNote(SESSION_RESPONSE_URI, actualResponseUri);
        }

        if (StringUtil.isNotBlank(error)) {
            return handleError(error, errorDescription, isDirectPostFlow);
        }

        boolean encryptionExpected = provider.getConfig().isEnforceHaip();
        if (encryptionExpected && !wasEncrypted) {
            return handleError(
                    "identity_provider_error",
                    "Encrypted response expected (direct_post.jwt) but received unencrypted vp_token.",
                    isDirectPostFlow);
        }

        return processVpToken(authSession, state, vpToken, isDirectPostFlow, isCrossDeviceFlow);
    }

    private record ResolvedKid(ECKey key, String state) {}

    private ResolvedKid resolveFromKid(String encryptedResponse) {
        String kid = responseDecryptor.extractKid(encryptedResponse);
        if (kid == null) return null;
        Oid4vpRequestObjectStore.KidEntry kidEntry = requestObjectStore.resolveByKid(session, kid);
        if (kidEntry == null || kidEntry.encryptionKeyJson() == null) return null;
        try {
            return new ResolvedKid(ECKey.parse(kidEntry.encryptionKeyJson()), kidEntry.state());
        } catch (Exception e) {
            LOG.warnf("Failed to parse encryption key from KID entry: %s", e.getMessage());
            return null;
        }
    }

    @GET
    @Path("/request-object/{request_handle}")
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response getRequestObject(
            @PathParam(PARAM_REQUEST_HANDLE) String requestHandle, @QueryParam(FLOW_PARAM) String flow) {
        return generateRequestObject(requestHandle, flow, null);
    }

    @POST
    @Path("/request-object/{request_handle}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response postRequestObject(
            @PathParam(PARAM_REQUEST_HANDLE) String requestHandle,
            @QueryParam(FLOW_PARAM) String flow,
            @FormParam(WALLET_NONCE) String walletNonce) {
        return generateRequestObject(requestHandle, flow, walletNonce);
    }

    private Response generateRequestObject(String requestHandle, String flow, String walletNonce) {
        if (StringUtil.isBlank(requestHandle)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing request handle");
        }

        Oid4vpRequestObjectStore.RequestHandleEntry handleEntry =
                requestObjectStore.resolveRequestHandle(session, requestHandle);
        if (handleEntry == null) {
            return jsonErrorResponse(Response.Status.NOT_FOUND, "not_found", "Request handle not found or expired");
        }

        AuthenticationSessionModel authSession =
                authSessionResolver.resolveFromTokenEntry(handleEntry.rootSessionId(), handleEntry.tabId());
        if (authSession == null) {
            return jsonErrorResponse(
                    Response.Status.BAD_REQUEST,
                    "session_expired",
                    "Authentication session expired. Please restart the login flow.");
        }

        try {
            String state = authSession.getAuthNote(SESSION_STATE);
            String nonce = authSession.getAuthNote(SESSION_NONCE);
            String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);

            String responseUri = computeResponseUri(flow);
            authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
            authSession.setAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI, responseUri);

            Oid4vpIdentityProviderConfig config = provider.getConfig();
            String dcqlQuery = provider.buildDcqlQueryFromConfig();

            SignedRequestObject signedRequest = provider.getRedirectFlowService()
                    .buildSignedRequestObject(new RequestObjectParams(
                            dcqlQuery,
                            config.getVerifierInfo(),
                            effectiveClientId,
                            config.getClientIdScheme(),
                            responseUri,
                            state,
                            nonce,
                            config.getX509CertificatePem(),
                            config.getX509SigningKeyJwk(),
                            walletNonce,
                            config.isEnforceHaip(),
                            provider.getLoginTimeoutSeconds()));

            if (signedRequest.encryptionKeyJson() != null) {
                String kid = Oid4vpRequestObjectStore.extractKidFromJwk(signedRequest.encryptionKeyJson());
                if (kid != null) {
                    requestObjectStore.storeKidIndex(session, kid, signedRequest.encryptionKeyJson(), state);
                }
            }

            return Response.ok(signedRequest.jwt())
                    .type(REQUEST_OBJECT_CONTENT_TYPE)
                    .build();
        } catch (Exception e) {
            LOG.errorf(e, "Failed to generate request object: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", e.getMessage());
        }
    }

    private String computeResponseUri(String flow) {
        String base = Oid4vpConstants.buildEndpointBaseUrl(
                session.getContext().getUri().getBaseUri(),
                realm.getName(),
                provider.getConfig().getAlias());
        if (FLOW_CROSS_DEVICE.equals(flow)) {
            return base + "?" + FLOW_PARAM + "=" + FLOW_CROSS_DEVICE;
        }
        return base;
    }

    @GET
    @Path("/cross-device/status")
    @Produces("text/event-stream")
    public Response crossDeviceStatus(@QueryParam(OAuth2Constants.STATE) String state) {
        if (StringUtil.isBlank(state)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state parameter");
        }

        return sseService.buildSseResponse(state);
    }

    @GET
    @Path("/cross-device/complete")
    public Response crossDeviceComplete(@QueryParam(PARAM_TOKEN) String token) {
        if (StringUtil.isBlank(token)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing token parameter");
        }
        return directPostService.handleCompletion(token);
    }

    @GET
    @Path("/complete-auth")
    public Response completeAuth(@QueryParam(OAuth2Constants.STATE) String state) {
        if (StringUtil.isBlank(state)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state parameter");
        }
        return directPostService.completeAuth(state, callback, event);
    }

    private Response processVpToken(
            AuthenticationSessionModel authSession,
            String state,
            String vpToken,
            boolean isDirectPostFlow,
            boolean isCrossDeviceFlow) {

        try {
            BrokeredIdentityContext context = provider.getCallbackProcessor().process(authSession, state, vpToken);

            if (isDirectPostFlow) {
                return handleDirectPostAuthentication(authSession, state, context, isCrossDeviceFlow);
            }

            context.setAuthenticationSession(authSession);
            event.event(EventType.LOGIN);
            return callback.authenticated(context);

        } catch (IdentityBrokerException e) {
            return handleError("identity_provider_error", e.getMessage(), isDirectPostFlow);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to process VP token: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", e.getMessage());
        }
    }

    private Response handleDirectPostAuthentication(
            AuthenticationSessionModel authSession,
            String state,
            BrokeredIdentityContext context,
            boolean isCrossDeviceFlow) {
        return directPostService.storeAndSignal(authSession, state, context, isCrossDeviceFlow);
    }

    private Response handleError(String error, String errorDescription, boolean isDirectPostFlow) {

        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, error)
                .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        if (isDirectPostFlow) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, error, errorDescription);
        }

        String message = error + (errorDescription != null ? ": " + errorDescription : "");
        return callback.error(getIdpModel(), message);
    }

    private Response jsonErrorResponse(Response.Status status, String error, String description) {
        try {
            Map<String, String> body = new HashMap<>();
            body.put(OAuth2Constants.ERROR, error);
            if (description != null) {
                body.put(OAuth2Constants.ERROR_DESCRIPTION, description);
            }
            String json = JsonSerialization.writeValueAsString(body);
            return Response.status(status)
                    .entity(json)
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            return Response.status(status)
                    .entity("{\"error\":\"" + error + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
