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

import de.arbeitsagentur.keycloak.oid4vp.domain.DecryptedResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCrossDeviceSseService;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpEndpointResponseFactory;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRequestObjectService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpResponseDecryptor;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * JAX-RS endpoint handling all OID4VP protocol interactions with wallets.
 *
 * <p>Exposes the following sub-resources:
 * <ul>
 *   <li>{@code POST /} — receives the wallet's direct_post response ({@code vp_token} or encrypted JWE)
 *   <li>{@code GET|POST /request-object/{handle}} — serves the signed (and optionally encrypted)
 *       authorization request object to the wallet
 *   <li>{@code GET /cross-device/status} — SSE stream for cross-device login polling
 *   <li>{@code GET /complete-auth} — finalizes authentication after the wallet's response is processed
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5 — Authorization Request</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Response Mode direct_post</a>
 */
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
    private final Oid4vpRequestObjectService requestObjectService;
    private final Oid4vpEndpointResponseFactory responseFactory;

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
        this.responseFactory = new Oid4vpEndpointResponseFactory(session, realm, provider.getConfig());
        this.directPostService = new Oid4vpDirectPostService(session, realm, provider.getConfig(), requestObjectStore);
        this.sseService = new Oid4vpCrossDeviceSseService(session, realm, provider.getConfig());
        this.requestObjectService = new Oid4vpRequestObjectService(
                session, provider, requestObjectStore, authSessionResolver, responseFactory);
    }

    /**
     * Handles GET requests to the endpoint. This is the error landing page for wallets that
     * redirect errors via GET (the {@code redirect_uri} from {@link #handleError}).
     * The state parameter is used to resolve the authentication session so that Keycloak's
     * standard error page template can be rendered via {@code callback.error()}.
     */
    @GET
    public Response handleGet(
            @QueryParam(OAuth2Constants.STATE) String state,
            @QueryParam(OAuth2Constants.ERROR) String error,
            @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        String message;
        if (StringUtil.isNotBlank(error)) {
            event.event(EventType.LOGIN_ERROR)
                    .detail(OAuth2Constants.ERROR, error)
                    .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                    .error(Errors.IDENTITY_PROVIDER_ERROR);
            message = error + (errorDescription != null ? ": " + errorDescription : "");
        } else {
            message = "No credential response received";
        }

        // Resolve the auth session from state so callback.error() can render Keycloak's error page.
        // callback.error() requires an active auth session in the KeycloakContext.
        if (StringUtil.isNotBlank(state)) {
            try {
                AuthenticationSessionModel authSession = authSessionResolver.resolveFromStore(state, null);
                if (authSession != null) {
                    session.getContext().setAuthenticationSession(authSession);
                }
            } catch (Exception e) {
                LOG.debugf("Could not resolve auth session from state: %s", e.getMessage());
            }
        }

        try {
            return callback.error(provider.getConfig(), message);
        } catch (Exception e) {
            LOG.warnf("Failed to render error page (auth session may have expired): %s", e.getMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Authentication failed: " + error)
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response handlePost(
            @FormParam(OAuth2Constants.STATE) String state,
            @FormParam(VP_TOKEN) String vpToken,
            @FormParam(ID_TOKEN) String idToken,
            @FormParam(RESPONSE) String encryptedResponse,
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        try {
            Oid4vpRequestObjectStore.RequestContextEntry requestContext = null;
            Oid4vpJwk kidBasedKey = null;

            if (StringUtil.isNotBlank(encryptedResponse)) {
                ResolvedKid resolved = resolveFromKid(encryptedResponse);
                if (resolved != null) {
                    kidBasedKey = resolved.key();
                    requestContext = resolved.requestContext();
                    if (StringUtil.isBlank(state)) {
                        state = requestContext != null ? requestContext.state() : null;
                    } else if (requestContext != null
                            && StringUtil.isNotBlank(requestContext.state())
                            && !state.equals(requestContext.state())) {
                        throw new IdentityBrokerException("Encrypted response state does not match the request state.");
                    }
                }
            }

            if (requestContext == null) {
                requestContext = requestObjectStore.resolveByState(session, state);
            }

            AuthenticationSessionModel authSession = authSessionResolver.resolveFromRequestContext(requestContext);

            if (authSession == null) {
                LOG.warnf(
                        "OID4VP callback session resolution failed: state=%s encrypted=%s requestContextPresent=%s",
                        state, StringUtil.isNotBlank(encryptedResponse), requestContext != null);
                event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
                return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "session_expired", null);
            }

            // Decrypt if encrypted
            boolean wasEncrypted = false;
            String mdocGeneratedNonce = null;
            if (StringUtil.isNotBlank(encryptedResponse)) {
                if (kidBasedKey == null) {
                    return handleError(
                            "identity_provider_error",
                            "Encrypted response could not be matched to a stored decryption key.",
                            state);
                }
                DecryptedResponse decrypted = responseDecryptor.decrypt(encryptedResponse, kidBasedKey);
                wasEncrypted = true;
                vpToken = decrypted.vpToken() != null ? decrypted.vpToken() : vpToken;
                idToken = decrypted.idToken() != null ? decrypted.idToken() : idToken;
                error = decrypted.error() != null ? decrypted.error() : error;
                errorDescription = decrypted.error() != null ? decrypted.errorDescription() : errorDescription;
                if (decrypted.mdocGeneratedNonce() != null) {
                    mdocGeneratedNonce = decrypted.mdocGeneratedNonce();
                }
            }

            if (StringUtil.isNotBlank(error)) {
                return handleError(error, errorDescription, state);
            }

            boolean encryptionExpected =
                    provider.getConfig().getResolvedResponseMode().requiresEncryption();
            if (encryptionExpected && !wasEncrypted) {
                return handleError(
                        "identity_provider_error",
                        "Encrypted response expected (direct_post.jwt) but received unencrypted vp_token.",
                        state);
            }

            return processVpToken(
                    authSession,
                    requestContext,
                    state,
                    vpToken,
                    idToken,
                    mdocGeneratedNonce,
                    FLOW_CROSS_DEVICE.equals(requestContext.flow()));
        } catch (IdentityBrokerException e) {
            return handleError("identity_provider_error", e.getMessage(), state);
        } catch (Exception e) {
            LOG.errorf(e, "Uncaught exception in handlePost: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private record ResolvedKid(Oid4vpJwk key, Oid4vpRequestObjectStore.RequestContextEntry requestContext) {}

    private ResolvedKid resolveFromKid(String encryptedResponse) {
        String kid = responseDecryptor.extractKid(encryptedResponse);
        if (kid == null) return null;
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestObjectStore.resolveByKid(session, kid);
        if (requestContext == null || requestContext.encryptionKeyJson() == null) return null;
        try {
            return new ResolvedKid(Oid4vpJwk.parse(requestContext.encryptionKeyJson()), requestContext);
        } catch (Exception e) {
            LOG.warnf("Failed to parse encryption key from KID entry: %s", e.getMessage());
            return null;
        }
    }

    @GET
    @Path("/request-object/{request_handle}")
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response getRequestObject(@PathParam(PARAM_REQUEST_HANDLE) String requestHandle) {
        return requestObjectService.generateRequestObject(requestHandle, null, null);
    }

    @POST
    @Path("/request-object/{request_handle}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response postRequestObject(
            @PathParam(PARAM_REQUEST_HANDLE) String requestHandle,
            @FormParam(WALLET_NONCE) String walletNonce,
            @FormParam(WALLET_METADATA) String walletMetadata) {
        return requestObjectService.generateRequestObject(requestHandle, walletNonce, walletMetadata);
    }

    @GET
    @Path("/cross-device/status")
    @Produces("text/event-stream")
    public void crossDeviceStatus(
            @QueryParam(PARAM_REQUEST_HANDLE) String requestHandle, @Context SseEventSink eventSink, @Context Sse sse) {
        if (StringUtil.isBlank(requestHandle)) {
            throw new BadRequestException("Missing request handle parameter");
        }
        AuthenticationSessionModel expectedAuthSession = directPostService.resolveExpectedAuthSession(requestHandle);
        if (expectedAuthSession == null) {
            throw stopSseReconnects();
        }
        AuthenticationSessionModel currentBrowserSession =
                authSessionResolver.resolveCurrentBrowserSession(expectedAuthSession);
        if (!authSessionResolver.sameAuthenticationSession(currentBrowserSession, expectedAuthSession)) {
            throw stopSseReconnects();
        }
        sseService.subscribe(requestHandle, eventSink, sse, expectedAuthSession);
    }

    @GET
    @Path("/complete-auth")
    public Response completeAuth(@QueryParam(PARAM_REQUEST_HANDLE) String requestHandle) {
        if (StringUtil.isBlank(requestHandle)) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Missing request handle parameter");
        }
        return directPostService.completeAuth(requestHandle, callback, event);
    }

    private Response processVpToken(
            AuthenticationSessionModel authSession,
            Oid4vpRequestObjectStore.RequestContextEntry requestContext,
            String state,
            String vpToken,
            String idToken,
            String mdocGeneratedNonce,
            boolean isCrossDeviceFlow) {

        try {
            BrokeredIdentityContext context =
                    provider.getCallbackProcessor().process(requestContext, vpToken, idToken, mdocGeneratedNonce);
            return directPostService.storeAndSignal(
                    authSession, requestContext.requestHandle(), context, isCrossDeviceFlow);
        } catch (IdentityBrokerException e) {
            return handleError("identity_provider_error", e.getMessage(), state);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to process VP token: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private Response handleError(String error, String errorDescription, String state) {

        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, error)
                .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        // Return a redirect_uri so the wallet can redirect the browser to the error page.
        // The GET handler renders the error via callback.error().
        // Include the state so the GET handler can resolve the auth session for Keycloak's error template.
        return responseFactory.jsonRedirectResponse(
                responseFactory.buildErrorRedirectUri(error, errorDescription, state));
    }

    /**
     * SSE resource methods with {@link SseEventSink} do not return a regular {@link Response} body.
     * Aborting the handshake with HTTP 204 is the SSE-compatible way to stop browser reconnects for
     * dead or mismatched login flows.
     */
    private WebApplicationException stopSseReconnects() {
        return new WebApplicationException(Response.noContent().build());
    }
}
