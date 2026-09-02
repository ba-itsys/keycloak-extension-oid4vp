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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
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
 * Handles the direct_post response mode. The wallet posts the VP token without the browser taking
 * part in that request, so the authentication cannot be completed inline. The brokered identity is
 * serialized into the authentication session and completion is signalled through a single-use
 * object, which the browser polls for in the cross-device flow and is redirected to in the
 * same-device flow.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2, Response Mode direct_post</a>
 */
public class Oid4vpDirectPostService {

    private static final Logger LOG = Logger.getLogger(Oid4vpDirectPostService.class);

    public static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    public static final String CROSS_DEVICE_FAILED_PREFIX = "oid4vp_failed:";
    public static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    public static final String FAILURE_PREFIX = "oid4vp_failure:";
    public static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    public static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";

    static final String KEY_ROOT_SESSION_ID = "root_session_id";
    static final String KEY_TAB_ID = "tab_id";
    static final String KEY_COMPLETE_AUTH_URL = "complete_auth_url";
    static final String KEY_FAILURE_URL = "failure_url";
    static final String KEY_RESPONSE_CODE = "response_code";
    static final String KEY_ORIGIN = "origin";
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

    public Response storeAndSignal(
            AuthenticationSessionModel authSession,
            String state,
            BrokeredIdentityContext context,
            boolean isCrossDevice) {

        // The first verified presentation for a state wins. A result whose deferred signal
        // /complete-auth has not consumed yet is not overwritten, so a later presentation submitted
        // to a known state, an attacker's own credential for example, cannot replace the identity
        // the first wallet established. Only a successfully verified presentation reaches this
        // method, so a wallet can still retry its own direct_post and a failed presentation never
        // locks the flow.
        Map<String, String> existing = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (existing != null && StringUtil.isNotBlank(existing.get(KEY_RESPONSE_CODE))) {
            LOG.debugf("Ignoring repeated direct_post for already-completed state=%s", state);
            return responseFactory.jsonRedirectResponse(
                    buildCompleteAuthUrl(state, existing.get(KEY_RESPONSE_CODE)), isCrossDevice);
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

        // A fresh, unguessable secret bound to this direct_post submission that the browser must
        // present back at /complete-auth, so the public state alone is not enough to drive
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

        return responseFactory.jsonRedirectResponse(completeAuthUrl, isCrossDevice);
    }

    public Response completeAuth(
            String state,
            String responseCode,
            AbstractIdentityProvider.AuthenticationCallback callback,
            EventBuilder event) {

        // The response_code is verified before anything is consumed. The state is public, so a
        // wrong code must neither complete the flow nor burn the legitimate user's single-use signal.
        Map<String, String> deferredSignal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (deferredSignal == null || !responseCodeMatches(deferredSignal.get(KEY_RESPONSE_CODE), responseCode)) {
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Oid4vpMessages.INVALID_LOGIN_RESPONSE);
        }

        AuthenticationSessionModel storedAuthSession = resolveExpectedAuthSession(state);
        if (storedAuthSession == null) {
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Oid4vpMessages.LOGIN_EXPIRED);
        }

        AuthenticationSessionModel currentBrowserSession =
                authSessionResolver.resolveCurrentBrowserSession(storedAuthSession);
        if (!authSessionResolver.sameAuthenticationSession(currentBrowserSession, storedAuthSession)) {
            return ErrorPage.error(
                    session,
                    currentBrowserSession,
                    Response.Status.BAD_REQUEST,
                    Oid4vpMessages.BROWSER_SESSION_MISMATCH);
        }
        // The broker callback runs on the current request-bound browser session. The stored session
        // only serves to recover the deferred broker state serialized earlier.
        AuthenticationSessionModel activeAuthSession = currentBrowserSession;

        session.singleUseObjects().remove(CROSS_DEVICE_COMPLETE_PREFIX + state);
        Map<String, String> consumedSignal = session.singleUseObjects().remove(DEFERRED_AUTH_PREFIX + state);
        if (consumedSignal == null) {
            return ErrorPage.error(
                    session, activeAuthSession, Response.Status.BAD_REQUEST, Oid4vpMessages.LOGIN_EXPIRED);
        }

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        storedAuthSession, deferredIdentityNote(state));
        if (serializedCtx == null) {
            return ErrorPage.error(
                    session, activeAuthSession, Response.Status.BAD_REQUEST, Oid4vpMessages.LOGIN_DATA_MISSING);
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
     * Names the auth note holding the identity a presentation established after the state that
     * presentation answered, so that {@code /complete-auth} reads back exactly the identity its
     * {@code response_code} was created for. One authentication session carries several live states
     * at a time, because every render of the wallet page allocates one for the same-device button
     * and one for the cross-device QR code, and returning to the login page adds more that stay live
     * until they expire. Under a single note name the presentation arriving last would decide a
     * login another presentation had already been verified for, and the single completion guard in
     * {@link #storeAndSignal} only covers repeated posts for the same state.
     */
    private static String deferredIdentityNote(String state) {
        return DEFERRED_IDENTITY_NOTE + ":" + state;
    }

    /** Names the auth note holding the presented credentials after its state, as above. */
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
     * Records a login that ended before it could be completed, either because the wallet reported an
     * error response (OID4VP 1.0 §8.5) or because this verifier rejected the presentation, and
     * returns the URL that hands the End-User back to the front channel, where {@code /failed}
     * returns them to the login page. OID4VP 1.0 §8.2 lets the Response URI return a
     * {@code redirect_uri} for Error Responses and requires the URL to carry a fresh,
     * cryptographically random value, which is the {@code response_code} created here. The failure
     * itself is kept server-side, so whoever posted cannot choose what the browser is told. In the
     * cross-device flow the wallet runs on another device, so the same URL is also published under
     * {@link #CROSS_DEVICE_FAILED_PREFIX} for the browser's SSE stream.
     */
    public String signalFailure(String state, LoginFailure failure, boolean isCrossDevice) {
        // The first failure recorded for a state owns the URL handed out with it, as on the
        // verified path. Recording a second one would generate a fresh response code and leave the
        // End-User holding a URL that resolves to nothing, which anyone who knows the public state
        // could cause by posting again.
        Map<String, String> existing = session.singleUseObjects().get(FAILURE_PREFIX + state);
        if (existing != null && StringUtil.isNotBlank(existing.get(KEY_RESPONSE_CODE))) {
            LOG.debugf("Ignoring repeated failure for already-failed state=%s", state);
            return buildFailureUrl(state, existing.get(KEY_RESPONSE_CODE));
        }

        String responseCode = Base64Url.encode(SecretGenerator.getInstance().randomBytes(RESPONSE_CODE_BYTES));
        String failureUrl = buildFailureUrl(state, responseCode);

        Map<String, String> entry = new HashMap<>();
        entry.put(KEY_RESPONSE_CODE, responseCode);
        entry.put(KEY_ORIGIN, failure.origin().name());
        entry.put(KEY_ERROR, failure.error() != null ? failure.error() : "");
        entry.put(KEY_ERROR_DESCRIPTION, failure.errorDescription() != null ? failure.errorDescription() : "");
        session.singleUseObjects().put(FAILURE_PREFIX + state, deferredAuthTtlSeconds, entry);

        if (isCrossDevice) {
            session.singleUseObjects()
                    .put(
                            CROSS_DEVICE_FAILED_PREFIX + state,
                            crossDeviceCompleteTtlSeconds,
                            Map.of(KEY_FAILURE_URL, failureUrl));
        }
        return failureUrl;
    }

    /**
     * Consumes the recorded failure for the given state and ends the attempt it belongs to, or
     * returns {@code null} when the state is unknown or the response code does not match the one
     * created for it. Callers that need the attempt's authentication session must resolve it before
     * calling this, because the request context it resolves through is dropped here.
     */
    public LoginFailure consumeFailure(String state, String responseCode) {
        Map<String, String> entry = session.singleUseObjects().get(FAILURE_PREFIX + state);
        if (entry == null || !responseCodeMatches(entry.get(KEY_RESPONSE_CODE), responseCode)) {
            return null;
        }
        session.singleUseObjects().remove(FAILURE_PREFIX + state);
        session.singleUseObjects().remove(CROSS_DEVICE_FAILED_PREFIX + state);
        // Dropping the request context of the abandoned attempt stops its state from serving a
        // request object and from accepting a presentation for the rest of the login timeout.
        // Otherwise a late response could reach an authentication session that has long moved on to
        // another attempt.
        requestObjectStore.removeRequestContext(session, state);
        return new LoginFailure(
                LoginFailure.Origin.of(entry.get(KEY_ORIGIN)), entry.get(KEY_ERROR), entry.get(KEY_ERROR_DESCRIPTION));
    }

    public record LoginFailure(Origin origin, String error, String errorDescription) {

        /**
         * Who ended the login. The origins differ in what the End-User is shown, because a wallet
         * that declines acts on the End-User's own choice and ends the login the way Keycloak ends
         * any refused brokered login, while a presentation this verifier rejected is a failure the
         * End-User cannot know about unless it is named.
         */
        public enum Origin {
            /** The wallet reported an error response (OID4VP 1.0 §8.5). */
            WALLET,
            /** The verifier refused what the wallet presented. */
            VERIFIER,
            /** Verification broke on this side. The presentation was never judged. */
            SERVER;

            static Origin of(String name) {
                for (Origin origin : values()) {
                    if (origin.name().equals(name)) {
                        return origin;
                    }
                }
                return WALLET;
            }
        }
    }

    public String buildFailureUrl(String state, String responseCode) {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias())
                + "/failed?"
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
