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
import static de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.PreDecryptionResult;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.domain.StoredRequestObject;
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
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
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
            @QueryParam("state") String state,
            @QueryParam("error") String error,
            @QueryParam("error_description") String errorDescription) {

        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null && state != null) {
            authSession = authSessionResolver.resolveFromStore(state, null);
        }

        if (StringUtil.isNotBlank(error)) {
            if (authSession != null) {
                return handleError(state, error, errorDescription, authSession, false, false);
            }
            event.event(EventType.LOGIN_ERROR)
                    .detail("error", error)
                    .detail("error_description", errorDescription)
                    .error(Errors.IDENTITY_PROVIDER_ERROR);
            return callback.error(getIdpModel(), error + (errorDescription != null ? ": " + errorDescription : ""));
        }

        return callback.error(getIdpModel(), "No credential response received");
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response handlePost(
            @QueryParam("state") String queryState,
            @QueryParam("tab_id") String tabId,
            @QueryParam("session_code") String sessionCode,
            @QueryParam("client_data") String clientData,
            @QueryParam("flow") String flow,
            @FormParam("state") String formState,
            @FormParam("vp_token") String vpToken,
            @FormParam("response") String encryptedResponse,
            @FormParam("error") String error,
            @FormParam("error_description") String errorDescription) {

        try {
            return handlePostInternal(
                    queryState,
                    tabId,
                    sessionCode,
                    clientData,
                    flow,
                    formState,
                    vpToken,
                    encryptedResponse,
                    error,
                    errorDescription);
        } catch (Exception e) {
            LOG.errorf(e, "Uncaught exception in handlePost: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", e.getMessage());
        }
    }

    private Response handlePostInternal(
            String queryState,
            String tabId,
            String sessionCode,
            String clientData,
            String flow,
            String formState,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription) {

        boolean isCrossDeviceFlow = "cross_device".equals(flow);
        String state = StringUtil.isNotBlank(queryState) ? queryState : formState;
        boolean hasError = StringUtil.isNotBlank(error);

        String preDecryptedMdocGeneratedNonce = null;
        if (StringUtil.isBlank(state) && StringUtil.isNotBlank(encryptedResponse)) {
            PreDecryptionResult preDecrypt =
                    responseDecryptor.tryPreDecrypt(encryptedResponse, requestObjectStore, session);
            if (preDecrypt.state() != null) {
                state = preDecrypt.state();
            }
            if (preDecrypt.vpToken() != null) {
                vpToken = preDecrypt.vpToken();
                encryptedResponse = null;
            }
            if (preDecrypt.error() != null) {
                error = preDecrypt.error();
                errorDescription = preDecrypt.errorDescription();
                hasError = true;
            }
            preDecryptedMdocGeneratedNonce = preDecrypt.mdocGeneratedNonce();
        }

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

        if (preDecryptedMdocGeneratedNonce != null) {
            authSession.setAuthNote(SESSION_MDOC_GENERATED_NONCE, preDecryptedMdocGeneratedNonce);
        }

        if (isDirectPostFlow) {
            String actualResponseUri = stripWalletQueryParams(
                    session.getContext().getUri().getRequestUri().toString());
            authSession.setAuthNote(SESSION_RESPONSE_URI, actualResponseUri);
        }

        if (hasError) {
            return handleError(state, error, errorDescription, authSession, isDirectPostFlow, isCrossDeviceFlow);
        }

        return processVpToken(
                authSession,
                state,
                vpToken,
                encryptedResponse,
                error,
                errorDescription,
                isDirectPostFlow,
                isCrossDeviceFlow);
    }

    @GET
    @Path("/request-object/{id}")
    @Produces("application/oauth-authz-req+jwt")
    public Response getRequestObject(@PathParam("id") String id) {
        if (StringUtil.isBlank(id)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing request object id");
        }

        StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            return jsonErrorResponse(Response.Status.NOT_FOUND, "not_found", "Request object not found or expired");
        }

        return Response.ok(stored.requestObjectJwt())
                .type("application/oauth-authz-req+jwt")
                .build();
    }

    @POST
    @Path("/request-object/{id}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/oauth-authz-req+jwt")
    public Response postRequestObject(
            @PathParam("id") String id,
            @FormParam("wallet_metadata") String walletMetadata,
            @FormParam("wallet_nonce") String walletNonce) {

        if (StringUtil.isBlank(id)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing request object id");
        }

        StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            return jsonErrorResponse(Response.Status.NOT_FOUND, "not_found", "Request object not found or expired");
        }

        if (StringUtil.isNotBlank(walletNonce) && stored.rebuildParams() != null) {
            return rebuildRequestObjectWithWalletNonce(stored, walletNonce);
        }

        return Response.ok(stored.requestObjectJwt())
                .type("application/oauth-authz-req+jwt")
                .build();
    }

    @GET
    @Path("/cross-device/status")
    @Produces("text/event-stream")
    public Response crossDeviceStatus(@QueryParam("state") String state) {
        if (StringUtil.isBlank(state)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state parameter");
        }

        return sseService.buildSseResponse(state);
    }

    @GET
    @Path("/cross-device/complete")
    public Response crossDeviceComplete(@QueryParam("token") String token, @QueryParam("source") String source) {
        if (StringUtil.isBlank(token)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing token parameter");
        }
        return directPostService.handleCompletion(token, source);
    }

    @GET
    @Path("/complete-auth")
    public Response completeAuth(@QueryParam("state") String state) {
        if (StringUtil.isBlank(state)) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state parameter");
        }
        return directPostService.completeAuth(state, callback, event);
    }

    private Response processVpToken(
            AuthenticationSessionModel authSession,
            String state,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription,
            boolean isDirectPostFlow,
            boolean isCrossDeviceFlow) {

        try {
            BrokeredIdentityContext context = provider.getCallbackProcessor()
                    .process(authSession, state, vpToken, encryptedResponse, error, errorDescription);

            if (isDirectPostFlow) {
                return handleDirectPostAuthentication(authSession, state, context, isCrossDeviceFlow);
            }

            context.setAuthenticationSession(authSession);
            event.event(EventType.LOGIN);
            return callback.authenticated(context);

        } catch (IdentityBrokerException e) {
            return handleError(
                    state, "identity_provider_error", e.getMessage(), authSession, isDirectPostFlow, isCrossDeviceFlow);
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

    private Response handleError(
            String state,
            String error,
            String errorDescription,
            AuthenticationSessionModel authSession,
            boolean isDirectPostFlow,
            boolean isCrossDeviceFlow) {

        event.event(EventType.LOGIN_ERROR)
                .detail("error", error)
                .detail("error_description", errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        if (isDirectPostFlow) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, error, errorDescription);
        }

        String message = error + (errorDescription != null ? ": " + errorDescription : "");
        return callback.error(getIdpModel(), message);
    }

    private Response rebuildRequestObjectWithWalletNonce(StoredRequestObject stored, String walletNonce) {
        try {
            SignedRequestObject rebuilt = provider.getRedirectFlowService()
                    .rebuildWithWalletNonce(
                            stored.rebuildParams(),
                            stored.state(),
                            stored.nonce(),
                            walletNonce,
                            provider.getLoginTimeoutSeconds());
            return Response.ok(rebuilt.jwt())
                    .type("application/oauth-authz-req+jwt")
                    .build();
        } catch (Exception e) {
            LOG.errorf(e, "Failed to rebuild request object with wallet_nonce: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private String stripWalletQueryParams(String uri) {
        if (uri == null) return null;
        try {
            URI parsed = URI.create(uri);
            String query = parsed.getQuery();
            if (query == null) return uri;

            StringBuilder cleanQuery = new StringBuilder();
            for (String param : query.split("&")) {
                String key = param.contains("=") ? param.substring(0, param.indexOf('=')) : param;
                if (!"state".equals(key)) {
                    if (cleanQuery.length() > 0) cleanQuery.append("&");
                    cleanQuery.append(param);
                }
            }

            String base = uri.contains("?") ? uri.substring(0, uri.indexOf('?')) : uri;
            return cleanQuery.length() > 0 ? base + "?" + cleanQuery : base;
        } catch (Exception e) {
            return uri;
        }
    }

    private Response jsonErrorResponse(Response.Status status, String error, String description) {
        try {
            Map<String, String> body = new HashMap<>();
            body.put("error", error);
            if (description != null) {
                body.put("error_description", description);
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
