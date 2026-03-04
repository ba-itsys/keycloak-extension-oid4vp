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
import de.arbeitsagentur.keycloak.oid4vp.domain.WalletMetadata;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCrossDeviceSseService;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectEncryptor;
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
import java.util.Map;
import java.util.UUID;
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
import org.keycloak.util.JsonSerialization;
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
            @QueryParam(FLOW_PARAM) String flow,
            @FormParam(OAuth2Constants.STATE) String state,
            @FormParam(VP_TOKEN) String vpToken,
            @FormParam(ID_TOKEN) String idToken,
            @FormParam(RESPONSE) String encryptedResponse,
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

        try {
            boolean isCrossDeviceFlow = FLOW_CROSS_DEVICE.equals(flow);

            // Resolve state + decryption key from KID when state is absent (direct_post.jwt flow)
            ECKey kidBasedKey = null;
            if (StringUtil.isBlank(state) && StringUtil.isNotBlank(encryptedResponse)) {
                ResolvedKid resolved = resolveFromKid(encryptedResponse);
                if (resolved != null) {
                    kidBasedKey = resolved.key();
                    state = resolved.state();
                }
            }

            // Resolve auth session from the state→session index
            AuthenticationSessionModel authSession = authSessionResolver.resolveFromStore(state, null);

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
                    idToken = decrypted.idToken() != null ? decrypted.idToken() : idToken;
                    error = decrypted.error() != null ? decrypted.error() : error;
                    errorDescription = decrypted.error() != null ? decrypted.errorDescription() : errorDescription;
                    if (decrypted.mdocGeneratedNonce() != null) {
                        authSession.setAuthNote(SESSION_MDOC_GENERATED_NONCE, decrypted.mdocGeneratedNonce());
                    }
                }
            }

            String actualResponseUri = UriBuilder.fromUri(
                            session.getContext().getUri().getRequestUri())
                    .replaceQueryParam(OAuth2Constants.STATE)
                    .build()
                    .toString();
            authSession.setAuthNote(SESSION_RESPONSE_URI, actualResponseUri);

            if (StringUtil.isNotBlank(error)) {
                return handleError(error, errorDescription, state);
            }

            boolean encryptionExpected = provider.getConfig().isEnforceHaip();
            if (encryptionExpected && !wasEncrypted) {
                return handleError(
                        "identity_provider_error",
                        "Encrypted response expected (direct_post.jwt) but received unencrypted vp_token.",
                        state);
            }

            return processVpToken(authSession, state, vpToken, idToken, isCrossDeviceFlow);
        } catch (Exception e) {
            LOG.errorf(e, "Uncaught exception in handlePost: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
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
        return generateRequestObject(requestHandle, flow, null, null);
    }

    @POST
    @Path("/request-object/{request_handle}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(REQUEST_OBJECT_CONTENT_TYPE)
    public Response postRequestObject(
            @PathParam(PARAM_REQUEST_HANDLE) String requestHandle,
            @QueryParam(FLOW_PARAM) String flow,
            @FormParam(WALLET_NONCE) String walletNonce,
            @FormParam(WALLET_METADATA) String walletMetadata) {
        return generateRequestObject(requestHandle, flow, walletNonce, walletMetadata);
    }

    private Response generateRequestObject(
            String requestHandle, String flow, String walletNonce, String walletMetadataJson) {
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
            String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);

            // Generate a fresh nonce for each request-object fetch to prevent replay attacks.
            // A captured VP token from a failed attempt must not be valid for subsequent requests.
            String nonce = UUID.randomUUID().toString();
            authSession.setAuthNote(SESSION_NONCE, nonce);

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
                            config.isUseIdTokenSubject()));

            if (signedRequest.encryptionKeyJson() != null) {
                String kid = Oid4vpRequestObjectStore.extractKidFromJwk(signedRequest.encryptionKeyJson());
                if (kid != null) {
                    requestObjectStore.storeKidIndex(session, kid, signedRequest.encryptionKeyJson(), state);
                }
                storeEncryptionJwkThumbprint(authSession, signedRequest.encryptionKeyJson());
            }

            String responseJwt = signedRequest.jwt();

            if (StringUtil.isNotBlank(walletMetadataJson)) {
                try {
                    WalletMetadata walletMeta = WalletMetadata.parse(walletMetadataJson);
                    responseJwt = Oid4vpRequestObjectEncryptor.encrypt(responseJwt, walletMeta);
                } catch (Exception e) {
                    LOG.warnf("Failed to encrypt request object per wallet_metadata: %s", e.getMessage());
                    return jsonErrorResponse(
                            Response.Status.BAD_REQUEST,
                            "invalid_request",
                            "Failed to encrypt request object with provided wallet_metadata");
                }
            }

            return Response.ok(responseJwt).type(REQUEST_OBJECT_CONTENT_TYPE).build();
        } catch (Exception e) {
            LOG.errorf(e, "Failed to generate request object: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private void storeEncryptionJwkThumbprint(AuthenticationSessionModel authSession, String encryptionKeyJson) {
        try {
            ECKey ecKey = ECKey.parse(encryptionKeyJson);
            byte[] thumbprint = ecKey.toPublicJWK().computeThumbprint("SHA-256").decode();
            String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint);
            authSession.setAuthNote(SESSION_ENCRYPTION_JWK_THUMBPRINT, encoded);
        } catch (Exception e) {
            LOG.warnf("Failed to compute JWK thumbprint for encryption key: %s", e.getMessage());
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
            String idToken,
            boolean isCrossDeviceFlow) {

        try {
            BrokeredIdentityContext context =
                    provider.getCallbackProcessor().process(authSession, state, vpToken, idToken);
            return directPostService.storeAndSignal(authSession, state, context, isCrossDeviceFlow);
        } catch (IdentityBrokerException e) {
            return handleError("identity_provider_error", e.getMessage(), state);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to process VP token: %s", e.getMessage());
            return jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        }
    }

    private Response handleError(String error, String errorDescription) {
        return handleError(error, errorDescription, null);
    }

    private Response handleError(String error, String errorDescription, String state) {

        event.event(EventType.LOGIN_ERROR)
                .detail(OAuth2Constants.ERROR, error)
                .detail(OAuth2Constants.ERROR_DESCRIPTION, errorDescription)
                .error(Errors.IDENTITY_PROVIDER_ERROR);

        // Return a redirect_uri so the wallet can redirect the browser to the error page.
        // The GET handler renders the error via callback.error().
        // Include the state so the GET handler can resolve the auth session for Keycloak's error template.
        String errorRedirectUri = buildErrorRedirectUri(error, errorDescription, state);
        return jsonRedirectResponse(errorRedirectUri);
    }

    private String buildErrorRedirectUri(String error, String errorDescription, String state) {
        String base = Oid4vpConstants.buildEndpointBaseUrl(
                session.getContext().getUri().getBaseUri(),
                realm.getName(),
                provider.getConfig().getAlias());
        UriBuilder builder = UriBuilder.fromUri(base);
        if (state != null) {
            builder.queryParam(OAuth2Constants.STATE, state);
        }
        builder.queryParam(OAuth2Constants.ERROR, error);
        if (errorDescription != null) {
            builder.queryParam(OAuth2Constants.ERROR_DESCRIPTION, errorDescription);
        }
        return builder.build().toString();
    }

    private Response jsonRedirectResponse(String redirectUri) {
        try {
            String json = JsonSerialization.writeValueAsString(Map.of(OAuth2Constants.REDIRECT_URI, redirectUri));
            return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            return Response.ok("{\"redirect_uri\":\"\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    private Response jsonErrorResponse(Response.Status status, String error, String description) {
        try {
            Object body = description != null
                    ? Map.of(OAuth2Constants.ERROR, error, OAuth2Constants.ERROR_DESCRIPTION, description)
                    : Map.of(OAuth2Constants.ERROR, error);
            return Response.status(status)
                    .entity(JsonSerialization.writeValueAsString(body))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            return Response.status(status)
                    .entity("{\"error\":\"server_error\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
