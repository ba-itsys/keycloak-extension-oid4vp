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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Handles the direct_post response mode for OID4VP.
 *
 * <p>In the direct_post flow, the wallet posts the VP token directly to the verifier's endpoint.
 * Since the browser is not involved in this HTTP request, the authentication cannot be completed
 * inline. Instead, this service serializes the brokered identity into the authentication session
 * and signals completion via a single-use object that the browser polls for (cross-device) or
 * redirects to (same-device).
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2 — Response Mode direct_post</a>
 */
public class Oid4vpDirectPostService {

    private static final Logger LOG = Logger.getLogger(Oid4vpDirectPostService.class);

    public static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    public static final String CROSS_DEVICE_FAILED_PREFIX = "oid4vp_failed:";
    public static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    public static final String WALLET_ERROR_PREFIX = "oid4vp_wallet_error:";
    public static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    public static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";

    static final String KEY_ROOT_SESSION_ID = "root_session_id";
    static final String KEY_TAB_ID = "tab_id";
    static final String KEY_COMPLETE_AUTH_URL = "complete_auth_url";
    static final String KEY_WALLET_ERROR_URL = "wallet_error_url";
    static final String KEY_RESPONSE_CODE = "response_code";
    static final String KEY_ERROR = "error";
    static final String KEY_ERROR_DESCRIPTION = "error_description";

    private static final int RESPONSE_CODE_BYTES = 32;

    private final long deferredAuthTtlSeconds;
    private final long crossDeviceCompleteTtlSeconds;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpConfigProvider config;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpEndpointResponseFactory responseFactory;

    public Oid4vpDirectPostService(
            KeycloakSession session,
            RealmModel realm,
            Oid4vpConfigProvider config,
            Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.config = config;
        this.requestObjectStore = requestObjectStore;
        this.authSessionResolver = new Oid4vpAuthSessionResolver(session, realm, requestObjectStore);
        this.responseFactory = new Oid4vpEndpointResponseFactory();
        this.deferredAuthTtlSeconds =
                realm != null ? realm.getAccessCodeLifespanLogin() : config.getCrossDeviceCompleteTtlSeconds();
        this.crossDeviceCompleteTtlSeconds = config.getCrossDeviceCompleteTtlSeconds();
    }

    /**
     * Stores the verified identity in the authentication session and signals completion.
     * For cross-device flows, returns an empty 200 OK (the browser polls via SSE).
     * For same-device flows, returns a JSON redirect to the complete-auth endpoint.
     */
    public Response storeAndSignal(
            AuthenticationSessionModel authSession,
            String state,
            BrokeredIdentityContext context,
            boolean isCrossDevice) {

        // Single-completion: the first verified presentation for a state wins. If a verified result is
        // already recorded (its deferred signal is still present, i.e. /complete-auth has not consumed
        // it yet), do not overwrite it; return the existing completion idempotently. This stops a later
        // presentation submitted to a known state (e.g. an attacker's own credential) from replacing the
        // identity the first wallet established, while still letting a wallet safely retry its own
        // direct_post. Only a successfully verified presentation reaches this method, so a failed
        // presentation never locks the flow and can be retried.
        Map<String, String> existing = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (existing != null && StringUtil.isNotBlank(existing.get(KEY_RESPONSE_CODE))) {
            LOG.debugf("Ignoring repeated direct_post for already-completed state=%s", state);
            return completionResponse(buildCompleteAuthUrl(state, existing.get(KEY_RESPONSE_CODE)), isCrossDevice);
        }

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String tabId = authSession.getTabId();

        context.setAuthenticationSession(authSession);
        SerializedBrokeredIdentityContext serialized = SerializedBrokeredIdentityContext.serialize(context);
        serialized.saveToAuthenticationSession(authSession, deferredIdentityNote(state));

        PresentedCredentials credentials = Oid4vpMapperUtils.presentedCredentials(context);
        if (credentials != null) {
            try {
                String credentialsJson = JsonSerialization.writeValueAsString(credentials);
                authSession.setAuthNote(deferredClaimsNote(state), credentialsJson);
            } catch (Exception e) {
                LOG.warnf("Failed to serialize the presented credentials: %s", e.getMessage());
            }
        }

        // Fresh, unguessable secret bound to this direct_post submission. The browser must present
        // it back at /complete-auth, so the public state alone is not sufficient to drive
        // completion (OID4VP 1.0 §8.2 response_code).
        String responseCode = Base64Url.encode(SecretGenerator.getInstance().randomBytes(RESPONSE_CODE_BYTES));
        String completeAuthUrl = buildCompleteAuthUrl(state, responseCode);
        session.singleUseObjects()
                .put(
                        DEFERRED_AUTH_PREFIX + state,
                        deferredAuthTtlSeconds,
                        Map.of(
                                KEY_ROOT_SESSION_ID,
                                rootSessionId != null ? rootSessionId : "",
                                KEY_TAB_ID,
                                tabId != null ? tabId : "",
                                KEY_RESPONSE_CODE,
                                responseCode));
        if (isCrossDevice) {
            session.singleUseObjects()
                    .put(
                            CROSS_DEVICE_COMPLETE_PREFIX + state,
                            crossDeviceCompleteTtlSeconds,
                            Map.of(KEY_COMPLETE_AUTH_URL, completeAuthUrl));
        }

        return completionResponse(completeAuthUrl, isCrossDevice);
    }

    private Response completionResponse(String completeAuthUrl, boolean isCrossDevice) {
        if (isCrossDevice) {
            return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
        }
        return responseFactory.jsonRedirectResponse(completeAuthUrl);
    }

    /**
     * Completes the authentication by deserializing the stored identity and invoking the
     * Keycloak authentication callback. Called by the browser after the wallet's direct_post
     * has been processed.
     */
    public Response completeAuth(
            String state,
            String responseCode,
            AbstractIdentityProvider.AuthenticationCallback callback,
            EventBuilder event) {

        // Verify the response_code before consuming anything: the state is public, so a wrong code
        // must neither complete the flow nor burn the legitimate user's single-use signal.
        Map<String, String> deferredSignal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (deferredSignal == null || !responseCodeMatches(deferredSignal.get(KEY_RESPONSE_CODE), responseCode)) {
            return ErrorPage.error(
                    session,
                    null,
                    Response.Status.BAD_REQUEST,
                    "Invalid or expired authentication response. Please try logging in again.");
        }

        AuthenticationSessionModel storedAuthSession = resolveExpectedAuthSession(state);
        if (storedAuthSession == null) {
            return ErrorPage.error(
                    session,
                    null,
                    Response.Status.BAD_REQUEST,
                    "Authentication session expired. Please try logging in again.");
        }

        AuthenticationSessionModel currentBrowserSession =
                authSessionResolver.resolveCurrentBrowserSession(storedAuthSession);
        if (!authSessionResolver.sameAuthenticationSession(currentBrowserSession, storedAuthSession)) {
            return ErrorPage.error(
                    session,
                    currentBrowserSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication session does not match the current browser session. Please restart the login flow.");
        }
        // Use the current request-bound browser session for the broker callback. The stored
        // session is only used to recover deferred broker state that was serialized earlier.
        AuthenticationSessionModel activeAuthSession = currentBrowserSession;

        session.singleUseObjects().remove(CROSS_DEVICE_COMPLETE_PREFIX + state);
        Map<String, String> consumedSignal = session.singleUseObjects().remove(DEFERRED_AUTH_PREFIX + state);
        if (consumedSignal == null) {
            return ErrorPage.error(
                    session,
                    activeAuthSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication session expired. Please try logging in again.");
        }

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        storedAuthSession, deferredIdentityNote(state));
        if (serializedCtx == null) {
            return ErrorPage.error(
                    session,
                    activeAuthSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication data not found. Please try logging in again.");
        }

        session.getContext().setAuthenticationSession(activeAuthSession);
        session.getContext().setClient(activeAuthSession.getClient());

        BrokeredIdentityContext context = serializedCtx.deserialize(session, storedAuthSession);
        context.setAuthenticationSession(activeAuthSession);
        context.getContextData().keySet().removeIf(key -> key.startsWith("user.attributes."));

        String credentialsJson = storedAuthSession.getAuthNote(deferredClaimsNote(state));
        if (credentialsJson != null) {
            try {
                PresentedCredentials credentials =
                        JsonSerialization.readValue(credentialsJson, PresentedCredentials.class);
                context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY, credentials);
            } catch (Exception e) {
                LOG.warnf("Failed to deserialize the presented credentials: %s", e.getMessage());
            }
            storedAuthSession.removeAuthNote(deferredClaimsNote(state));
        }

        storedAuthSession.removeAuthNote(deferredIdentityNote(state));

        event.event(EventType.LOGIN);
        Response response = callback.authenticated(context);
        requestObjectStore.removeRequestContext(session, state);
        return response;
    }

    /**
     * The auth note holding the identity a presentation established, named after the state that
     * presentation answered.
     *
     * <p>One authentication session carries several live states at a time: each render of the
     * wallet page allocates one for the same-device button and one for the cross-device QR code,
     * and returning to the login page to start over adds more while the earlier ones stay live
     * until they expire. Under a single note name the presentation that arrives last would decide
     * the login another presentation had already been verified for, since the single-completion
     * guard in {@link #storeAndSignal} only covers repeated posts for the same state. Naming the
     * notes after their state means {@code /complete-auth} reads back exactly the identity the
     * {@code response_code} it was given was minted for.
     */
    private static String deferredIdentityNote(String state) {
        return DEFERRED_IDENTITY_NOTE + ":" + state;
    }

    /** The auth note holding the presented credentials, named after the state as above. */
    private static String deferredClaimsNote(String state) {
        return DEFERRED_CLAIMS_NOTE + ":" + state;
    }

    private static boolean responseCodeMatches(String expected, String provided) {
        if (StringUtil.isBlank(expected) || StringUtil.isBlank(provided)) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), provided.getBytes(StandardCharsets.UTF_8));
    }

    public AuthenticationSessionModel resolveExpectedAuthSession(String state) {
        Map<String, String> signal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (signal != null) {
            AuthenticationSessionModel authSession =
                    authSessionResolver.resolveFromTokenEntry(signal.get(KEY_ROOT_SESSION_ID), signal.get(KEY_TAB_ID));
            if (authSession != null) {
                return authSession;
            }
        }

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestObjectStore.resolveByState(session, state);
        if (requestContext == null) {
            return null;
        }
        return authSessionResolver.resolveFromTokenEntry(requestContext.rootSessionId(), requestContext.tabId());
    }

    /**
     * Records a wallet-reported error response (OID4VP 1.0 §8.5) and returns the URL that hands the
     * End-User back to the front channel, where {@code /wallet-error} returns them to the login
     * page.
     *
     * <p>OID4VP 1.0 §8.2 lets the Response URI return a {@code redirect_uri} "in response to
     * successful Authorization Responses or for Error Responses", and requires the URL to carry a
     * fresh, cryptographically random value, which is the {@code response_code} minted here. The
     * error itself is kept server-side so the wallet cannot choose what the client is told.
     *
     * <p>For cross-device flows the wallet runs on another device, so the same URL is additionally
     * published under {@link #CROSS_DEVICE_FAILED_PREFIX} for the browser's SSE stream to pick up.
     */
    public String signalWalletError(String state, String error, String errorDescription, boolean isCrossDevice) {
        String responseCode = Base64Url.encode(SecretGenerator.getInstance().randomBytes(RESPONSE_CODE_BYTES));
        String walletErrorUrl = buildWalletErrorUrl(state, responseCode);

        Map<String, String> entry = new HashMap<>();
        entry.put(KEY_RESPONSE_CODE, responseCode);
        entry.put(KEY_ERROR, error != null ? error : "");
        entry.put(KEY_ERROR_DESCRIPTION, errorDescription != null ? errorDescription : "");
        session.singleUseObjects().put(WALLET_ERROR_PREFIX + state, deferredAuthTtlSeconds, entry);

        if (isCrossDevice) {
            session.singleUseObjects()
                    .put(
                            CROSS_DEVICE_FAILED_PREFIX + state,
                            crossDeviceCompleteTtlSeconds,
                            Map.of(KEY_WALLET_ERROR_URL, walletErrorUrl));
        }
        return walletErrorUrl;
    }

    /**
     * Consumes the recorded wallet error for the given state and ends the attempt it belongs to,
     * or returns {@code null} when the state is unknown or the response code does not match the
     * one minted for it. Callers that need the attempt's authentication session must resolve it
     * before calling this, because the request context it resolves through is dropped here.
     */
    public WalletError consumeWalletError(String state, String responseCode) {
        Map<String, String> entry = session.singleUseObjects().get(WALLET_ERROR_PREFIX + state);
        if (entry == null || !responseCodeMatches(entry.get(KEY_RESPONSE_CODE), responseCode)) {
            return null;
        }
        session.singleUseObjects().remove(WALLET_ERROR_PREFIX + state);
        session.singleUseObjects().remove(CROSS_DEVICE_FAILED_PREFIX + state);
        // The End-User is being handed back to the login page, so this attempt is over. Dropping
        // its request context stops the abandoned state from serving its request object and
        // accepting a presentation for the rest of the login timeout, which is what let a late
        // response reach an authentication session that has long moved on to another attempt.
        requestObjectStore.removeRequestContext(session, state);
        return new WalletError(entry.get(KEY_ERROR), entry.get(KEY_ERROR_DESCRIPTION));
    }

    /** A wallet-reported error response, as recorded when it arrived at the response URI. */
    public record WalletError(String error, String errorDescription) {}

    public String buildWalletErrorUrl(String state, String responseCode) {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias())
                + "/wallet-error?"
                + Oid4vpConstants.PARAM_STATE + "=" + URLEncoder.encode(state, StandardCharsets.UTF_8)
                + "&"
                + Oid4vpConstants.PARAM_RESPONSE_CODE + "=" + URLEncoder.encode(responseCode, StandardCharsets.UTF_8);
    }

    public String buildCompleteAuthUrl(String state, String responseCode) {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias())
                + "/complete-auth?"
                + Oid4vpConstants.PARAM_STATE + "=" + URLEncoder.encode(state, StandardCharsets.UTF_8)
                + "&"
                + Oid4vpConstants.PARAM_RESPONSE_CODE + "=" + URLEncoder.encode(responseCode, StandardCharsets.UTF_8);
    }
}
