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
import java.util.concurrent.TimeUnit;
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
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2 — Response Mode direct_post</a>
 */
public class Oid4vpIdentityProviderEndpoint {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderEndpoint.class);
    private static final int REQUEST_CONTEXT_LOOKUP_MAX_ATTEMPTS = 5;
    private static final long REQUEST_CONTEXT_LOOKUP_RETRY_DELAY_MILLIS = 25;

    /** Message bundle key of the text the login page shows for a rejected presentation. */
    static final String PRESENTATION_REJECTED_MESSAGE = "oid4vpPresentationRejected";

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
        this.responseFactory = new Oid4vpEndpointResponseFactory();
        this.directPostService = new Oid4vpDirectPostService(session, realm, provider.getConfig(), requestObjectStore);
        this.sseService = new Oid4vpCrossDeviceSseService(session, realm, provider.getConfig());
        this.requestObjectService = new Oid4vpRequestObjectService(
                session, provider, requestObjectStore, authSessionResolver, responseFactory);
    }

    /**
     * Handles GET requests to the endpoint. This is the landing page for wallets that redirect an
     * error to the response URI by themselves rather than posting it and following the {@code
     * redirect_uri} to {@link #handleFailureRedirect}. The state parameter is used to resolve the
     * authentication session so that Keycloak's standard error page template can be rendered via
     * {@code callback.error()}.
     *
     * <p>Nothing authenticates this request, so the error it names is whatever its caller wrote.
     * It ends the login it names without touching the request context, and the text it carries
     * reaches the error page, so it is a landing page for wallets that need it rather than a
     * trusted signal.
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

        // callback.error() requires an active auth session in the KeycloakContext.
        if (StringUtil.isNotBlank(state)) {
            try {
                AuthenticationSessionModel authSession = authSessionResolver.resolveFromStore(state);
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
            @FormParam(RESPONSE) String encryptedResponse,
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        try {
            IncomingPost incomingPost = new IncomingPost(state, vpToken, encryptedResponse, error, errorDescription);
            ResolvedRequest resolvedRequest = resolveRequest(incomingPost.state(), incomingPost.encryptedResponse());
            AuthenticationSessionModel authSession =
                    authSessionResolver.resolveFromRequestContext(resolvedRequest.requestContext());
            if (authSession == null) {
                return sessionExpiredResponse(
                        resolvedRequest.state(), incomingPost.encryptedResponse(), resolvedRequest.requestContext());
            }

            ResolvedSubmission submission = resolveSubmission(incomingPost, resolvedRequest);
            // Under direct_post.jwt the wallet's error responses arrive in the response JWE too
            // (OID4VP 1.0 §8.3). Checking the encryption requirement before the error branch keeps
            // an unencrypted post from recording attacker-chosen error details as a wallet error
            // and being answered with 200.
            ensureEncryptedWhenRequired(submission.wasEncrypted());
            if (StringUtil.isNotBlank(submission.error())) {
                return handleWalletError(
                        submission.error(),
                        submission.errorDescription(),
                        resolvedRequest.state(),
                        FLOW_CROSS_DEVICE.equals(
                                resolvedRequest.requestContext().flow()));
            }

            return processVpToken(
                    authSession,
                    resolvedRequest.requestContext(),
                    submission.state(),
                    submission.vpToken(),
                    submission.mdocGeneratedNonce(),
                    FLOW_CROSS_DEVICE.equals(resolvedRequest.requestContext().flow()));
        } catch (IdentityBrokerException e) {
            return handleError("identity_provider_error", e.getMessage());
        } catch (Exception e) {
            LOG.errorf(e, "Uncaught exception in handlePost: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private record IncomingPost(
            String state, String vpToken, String encryptedResponse, String error, String errorDescription) {}

    private record ResolvedRequest(
            String state, Oid4vpRequestObjectStore.RequestContextEntry requestContext, Oid4vpJwk kidBasedKey) {}

    private record ResolvedSubmission(
            String state,
            String vpToken,
            String error,
            String errorDescription,
            String mdocGeneratedNonce,
            boolean wasEncrypted) {}

    private ResolvedRequest resolveRequest(String state, String encryptedResponse) {
        // The response-encryption JWK is created with kid == state, so an encrypted callback that
        // omits the state form field still resolves through the cleartext JWE header kid.
        String kid = StringUtil.isNotBlank(encryptedResponse) ? responseDecryptor.extractKid(encryptedResponse) : null;

        String lookupState = StringUtil.isNotBlank(state) ? state : kid;

        // A direct_post.jwt callback can land on a different node immediately after the request
        // object was created. In that case the state index may exist logically but still be
        // briefly invisible via the shared single-use store, so we retry with a short bounded pause.
        for (int attempt = 1; attempt <= REQUEST_CONTEXT_LOOKUP_MAX_ATTEMPTS; attempt++) {
            Oid4vpRequestObjectStore.RequestContextEntry requestContext =
                    requestObjectStore.resolveByState(session, lookupState);

            if (requestContext != null || attempt == REQUEST_CONTEXT_LOOKUP_MAX_ATTEMPTS || kid == null) {
                if (attempt > 1 && requestContext != null) {
                    LOG.debugf(
                            "OID4VP callback request context became visible after %d lookup attempts: state=%s kid=%s",
                            attempt, requestContext.state(), kid);
                }
                String resolvedState = requestContext != null ? requestContext.state() : state;
                Oid4vpJwk kidBasedKey = parseEncryptionKey(requestContext);
                return new ResolvedRequest(resolvedState, requestContext, kidBasedKey);
            }

            pauseRequestContextLookup();
        }

        return new ResolvedRequest(state, null, null);
    }

    private Response sessionExpiredResponse(
            String state, String encryptedResponse, Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        LOG.warnf(
                "OID4VP callback session resolution failed: state=%s encrypted=%s requestContextPresent=%s",
                state, StringUtil.isNotBlank(encryptedResponse), requestContext != null);
        event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
        return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "session_expired", null);
    }

    private ResolvedSubmission resolveSubmission(IncomingPost incomingPost, ResolvedRequest resolvedRequest) {
        if (StringUtil.isBlank(incomingPost.encryptedResponse())) {
            return new ResolvedSubmission(
                    resolvedRequest.state(),
                    incomingPost.vpToken(),
                    incomingPost.error(),
                    incomingPost.errorDescription(),
                    null,
                    false);
        }
        if (resolvedRequest.kidBasedKey() == null) {
            throw new IdentityBrokerException("Encrypted response could not be matched to a stored decryption key.");
        }

        DecryptedResponse decrypted =
                responseDecryptor.decrypt(incomingPost.encryptedResponse(), resolvedRequest.kidBasedKey());
        String resolvedState = resolveEncryptedResponseState(
                resolvedRequest.requestContext(), incomingPost.state(), decrypted.state());
        return new ResolvedSubmission(
                resolvedState,
                decrypted.vpToken(),
                decrypted.error(),
                decrypted.errorDescription(),
                decrypted.mdocGeneratedNonce(),
                true);
    }

    private String resolveEncryptedResponseState(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, String formState, String responseState) {
        if (requestContext == null || StringUtil.isBlank(requestContext.state())) {
            throw new IdentityBrokerException("Encrypted response could not be matched to a stored request state.");
        }
        if (StringUtil.isBlank(responseState)) {
            throw new IdentityBrokerException("Encrypted response payload is missing the state parameter.");
        }
        String expectedState = requestContext.state();
        if (!expectedState.equals(responseState)) {
            throw new IdentityBrokerException("Encrypted response state does not match the request state.");
        }
        if (StringUtil.isNotBlank(formState) && !formState.equals(responseState)) {
            throw new IdentityBrokerException("Encrypted response state does not match the request state.");
        }
        return responseState;
    }

    private void ensureEncryptedWhenRequired(boolean wasEncrypted) {
        boolean encryptionExpected =
                provider.getConfig().getResolvedResponseMode().requiresEncryption();
        if (encryptionExpected && !wasEncrypted) {
            throw new IdentityBrokerException(
                    "Encrypted response expected (direct_post.jwt) but received unencrypted vp_token.");
        }
    }

    private Oid4vpJwk parseEncryptionKey(Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        if (requestContext == null || requestContext.encryptionKeyJson() == null) {
            return null;
        }
        try {
            return Oid4vpJwk.parse(requestContext.encryptionKeyJson());
        } catch (Exception e) {
            LOG.warnf("Failed to parse encryption key from stored request context: %s", e.getMessage());
            return null;
        }
    }

    private void pauseRequestContextLookup() {
        try {
            // Sleeping here is intentional: repeated reads without time passing do not help when
            // the request-context indexes are still propagating across nodes.
            TimeUnit.MILLISECONDS.sleep(REQUEST_CONTEXT_LOOKUP_RETRY_DELAY_MILLIS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @GET
    @Path("/request-object/{state}")
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response getRequestObject(@PathParam(PARAM_STATE) String state) {
        return requestObjectService.generateRequestObject(state, null, null);
    }

    @POST
    @Path("/request-object/{state}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response postRequestObject(
            @PathParam(PARAM_STATE) String state,
            @FormParam(WALLET_NONCE) String walletNonce,
            @FormParam(WALLET_METADATA) String walletMetadata) {
        return requestObjectService.generateRequestObject(state, walletNonce, walletMetadata);
    }

    @GET
    @Path("/cross-device/status")
    @Produces("text/event-stream")
    public void crossDeviceStatus(
            @QueryParam(PARAM_STATE) String state, @Context SseEventSink eventSink, @Context Sse sse) {
        if (StringUtil.isBlank(state)) {
            throw new BadRequestException("Missing state parameter");
        }
        AuthenticationSessionModel expectedAuthSession = directPostService.resolveExpectedAuthSession(state);
        if (expectedAuthSession == null) {
            throw stopSseReconnects();
        }
        AuthenticationSessionModel currentBrowserSession =
                authSessionResolver.resolveCurrentBrowserSession(expectedAuthSession);
        if (!authSessionResolver.sameAuthenticationSession(currentBrowserSession, expectedAuthSession)) {
            throw stopSseReconnects();
        }
        sseService.subscribe(state, eventSink, sse, expectedAuthSession);
    }

    @GET
    @Path("/complete-auth")
    public Response completeAuth(
            @QueryParam(PARAM_STATE) String state, @QueryParam(PARAM_RESPONSE_CODE) String responseCode) {
        if (StringUtil.isBlank(state)) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Missing state parameter");
        }
        if (StringUtil.isBlank(responseCode)) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Missing response code parameter");
        }
        return directPostService.completeAuth(state, responseCode, callback, event);
    }

    /**
     * Front-channel landing point for a presentation that ended without completing the login,
     * either because the wallet reported an error response (OID4VP 1.0 §8.5) or because this
     * verifier rejected what the wallet presented. The wallet sends the End-User here after the
     * response URI answered it, which is the only way control returns to the browser when the
     * response itself travels the back channel.
     *
     * <p>How the login ends follows from who ended it. A wallet declining is a step in the login,
     * not a failure of it, so {@code callback.cancelled()} returns the End-User to the login page
     * with the standard "access denied" message, exactly as Keycloak ends any refused brokered
     * login. A presentation this verifier rejected is something the End-User cannot otherwise
     * learn about, so {@code callback.error()} names it on the login page instead. Either way the
     * client is deliberately not sent an OAuth error: another attempt or another authentication
     * method is still possible.
     *
     * <p>The error code and description are read from the server-side record rather than from
     * query parameters, so they cannot be chosen by whoever opens this URL, and the response code
     * proves the caller is the End-User of the wallet that posted rather than anyone who learned
     * the state. They are recorded on the login event and not shown: OID4VP 1.0 §8.5 spans
     * everything from a declined presentation to a request the wallet could not parse and nothing
     * authenticates which of them actually happened, and a rejection reason is an internal
     * verification message rather than something an End-User can act on.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5">OID4VP 1.0 §8.5 — Error Response</a>
     */
    @GET
    @Path("/failed")
    public Response handleFailureRedirect(
            @QueryParam(PARAM_STATE) String state, @QueryParam(PARAM_RESPONSE_CODE) String responseCode) {
        if (StringUtil.isBlank(state) || StringUtil.isBlank(responseCode)) {
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Missing state or response code parameter");
        }

        AuthenticationSessionModel authSession = authSessionResolver.resolveFromStore(state);
        Oid4vpDirectPostService.LoginFailure failure = directPostService.consumeFailure(state, responseCode);
        if (failure == null) {
            LOG.warnf("No failure recorded for state=%s, or the response code did not match", state);
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request", "Unknown or already consumed failure");
        }
        if (authSession == null) {
            LOG.warnf("The failed login for state=%s has no authentication session left to return to", state);
            return responseFactory.jsonErrorResponse(
                    Response.Status.BAD_REQUEST, "session_expired", "The login this error belongs to has expired");
        }
        session.getContext().setAuthenticationSession(authSession);

        LOG.debugf(
                "Returning to the login page for state=%s after %s error '%s': %s",
                state, failure.origin(), failure.error(), failure.errorDescription());
        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, failure.error())
                .detail(OAuth2Constants.ERROR_DESCRIPTION, failure.errorDescription())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        if (failure.origin() == Oid4vpDirectPostService.LoginFailure.Origin.VERIFIER) {
            return callback.error(provider.getConfig(), PRESENTATION_REJECTED_MESSAGE);
        }
        return callback.cancelled(provider.getConfig());
    }

    private Response processVpToken(
            AuthenticationSessionModel authSession,
            Oid4vpRequestObjectStore.RequestContextEntry requestContext,
            String state,
            String vpToken,
            String mdocGeneratedNonce,
            boolean isCrossDeviceFlow) {

        try {
            BrokeredIdentityContext context =
                    provider.getCallbackProcessor().process(requestContext, vpToken, mdocGeneratedNonce);
            return directPostService.storeAndSignal(authSession, requestContext.state(), context, isCrossDeviceFlow);
        } catch (IdentityBrokerException e) {
            return handleVerificationFailure(e.getMessage(), state, isCrossDeviceFlow);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to process VP token: %s", e.getMessage());
            return responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    /**
     * Answers a post that failed before its presentation could be verified: an unresolvable state,
     * a response that could not be decrypted, or one that arrived unencrypted where encryption is
     * required. Nothing here proves the post came from the wallet whose login it names, so it is
     * answered with a plain error and the attempt it claims to belong to is left alone: a
     * front-channel return would hand whoever posted a way to end a login they only know the state
     * of.
     */
    private Response handleError(String error, String errorDescription) {
        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, error)
                .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        return responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, error, errorDescription);
    }

    /**
     * Answers a wallet-reported error response (OID4VP 1.0 §8.5). The status is 200 because the
     * response URI processed the Authorization Error Response successfully (OID4VP 1.0 §8.2); the
     * error belongs in the body, not in the HTTP status.
     *
     * <p>The body also carries a {@code redirect_uri}, which §8.2 explicitly permits for error
     * responses and which the wallet MUST follow. Without it the wallet has nowhere to send the
     * End-User and the login stalls until it times out. The URL leads to
     * {@link #handleFailureRedirect}, which returns them to the login page.
     */
    private Response handleWalletError(String error, String errorDescription, String state, boolean isCrossDevice) {
        return handleFailure(
                new Oid4vpDirectPostService.LoginFailure(
                        Oid4vpDirectPostService.LoginFailure.Origin.WALLET, error, errorDescription),
                state,
                isCrossDevice,
                Response.Status.OK);
    }

    /**
     * Answers a presentation this verifier rejected. The wallet is told what was wrong, and the
     * body carries the {@code redirect_uri} that hands the End-User back to the login page, for
     * the same reason a wallet-reported error does: the response travelled the back channel, so
     * without it the browser is left waiting on a login that has already failed.
     *
     * <p>Unlike a wallet-reported error the status stays 400. The response was not acceptable,
     * and a rejected presentation answered with a success status is what the OID4VP conformance
     * suite's negative verifier modules read as a verifier that did not reject at all.
     *
     * <p>Only a response that got as far as being verified is answered this way. The transport
     * level failures {@link #handlePost} catches are answered with a plain error instead, because
     * a post that never proved it came from the wallet must not be able to end the attempt.
     */
    private Response handleVerificationFailure(String errorDescription, String state, boolean isCrossDevice) {
        return handleFailure(
                new Oid4vpDirectPostService.LoginFailure(
                        Oid4vpDirectPostService.LoginFailure.Origin.VERIFIER, "invalid_presentation", errorDescription),
                state,
                isCrossDevice,
                Response.Status.BAD_REQUEST);
    }

    /**
     * Records the failure, then answers the wallet with the error alongside the {@code
     * redirect_uri} it must follow, under the status the caller says the response deserves.
     * Without a state there is nothing to record and nowhere to send the End-User, so the response
     * falls back to the plain error the wallet can still act on.
     */
    private Response handleFailure(
            Oid4vpDirectPostService.LoginFailure failure, String state, boolean isCrossDevice, Response.Status status) {
        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, failure.error())
                .detail(OAuth2Constants.ERROR_DESCRIPTION, failure.errorDescription())
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        if (StringUtil.isBlank(state)) {
            return responseFactory.jsonErrorResponse(status, failure.error(), failure.errorDescription());
        }
        String failureUrl = directPostService.signalFailure(state, failure, isCrossDevice);
        return responseFactory.jsonErrorRedirectResponse(
                status, failure.error(), failure.errorDescription(), failureUrl);
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
