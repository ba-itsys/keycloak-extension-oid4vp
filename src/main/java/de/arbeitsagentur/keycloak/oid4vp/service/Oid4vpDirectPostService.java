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
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * Handles the direct_post response mode for OID4VP.
 *
 * <p>In the direct_post flow, the wallet posts the VP token directly to the verifier's endpoint.
 * Since the browser is not involved in this HTTP request, the authentication cannot be completed
 * inline. Instead, this service serializes the brokered identity into the authentication session
 * and signals completion via a single-use object that the browser polls for (cross-device) or
 * redirects to (same-device).
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Response Mode direct_post</a>
 */
public class Oid4vpDirectPostService {

    private static final Logger LOG = Logger.getLogger(Oid4vpDirectPostService.class);

    public static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    public static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    public static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    public static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";

    static final String KEY_ROOT_SESSION_ID = "root_session_id";
    static final String KEY_TAB_ID = "tab_id";
    static final String KEY_COMPLETE_AUTH_URL = "complete_auth_url";

    private final long deferredAuthTtlSeconds;
    private final long crossDeviceCompleteTtlSeconds;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpConfigProvider config;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final Oid4vpAuthSessionResolver authSessionResolver;

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
            String requestHandle,
            BrokeredIdentityContext context,
            boolean isCrossDevice) {

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String tabId = authSession.getTabId();

        context.setAuthenticationSession(authSession);
        SerializedBrokeredIdentityContext serialized = SerializedBrokeredIdentityContext.serialize(context);
        serialized.saveToAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);

        @SuppressWarnings("unchecked")
        Map<String, Object> claims =
                (Map<String, Object>) context.getContextData().get(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY);
        if (claims != null) {
            try {
                String claimsJson = JsonSerialization.writeValueAsString(claims);
                authSession.setAuthNote(DEFERRED_CLAIMS_NOTE, claimsJson);
            } catch (Exception e) {
                LOG.warnf("Failed to serialize claims: %s", e.getMessage());
            }
        }

        String completeAuthUrl = buildCompleteAuthUrl(requestHandle);
        session.singleUseObjects()
                .put(
                        DEFERRED_AUTH_PREFIX + requestHandle,
                        deferredAuthTtlSeconds,
                        Map.of(
                                KEY_ROOT_SESSION_ID,
                                rootSessionId != null ? rootSessionId : "",
                                KEY_TAB_ID,
                                tabId != null ? tabId : ""));
        if (isCrossDevice) {
            session.singleUseObjects()
                    .put(
                            CROSS_DEVICE_COMPLETE_PREFIX + requestHandle,
                            crossDeviceCompleteTtlSeconds,
                            Map.of(KEY_COMPLETE_AUTH_URL, completeAuthUrl));
        }

        if (isCrossDevice) {
            return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
        }
        return Oid4vpEndpointResponseFactory.jsonRedirectResponse(completeAuthUrl);
    }

    /**
     * Completes the authentication by deserializing the stored identity and invoking the
     * Keycloak authentication callback. Called by the browser after the wallet's direct_post
     * has been processed.
     */
    public Response completeAuth(
            String requestHandle, AbstractIdentityProvider.AuthenticationCallback callback, EventBuilder event) {

        AuthenticationSessionModel storedAuthSession = resolveExpectedAuthSession(requestHandle);
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

        session.singleUseObjects().remove(CROSS_DEVICE_COMPLETE_PREFIX + requestHandle);
        Map<String, String> consumedSignal = session.singleUseObjects().remove(DEFERRED_AUTH_PREFIX + requestHandle);
        if (consumedSignal == null) {
            return ErrorPage.error(
                    session,
                    currentBrowserSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication session expired. Please try logging in again.");
        }

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        storedAuthSession, DEFERRED_IDENTITY_NOTE);
        if (serializedCtx == null) {
            return ErrorPage.error(
                    session,
                    storedAuthSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication data not found. Please try logging in again.");
        }

        session.getContext().setAuthenticationSession(storedAuthSession);
        session.getContext().setClient(storedAuthSession.getClient());

        BrokeredIdentityContext context = serializedCtx.deserialize(session, storedAuthSession);
        context.setAuthenticationSession(storedAuthSession);
        context.getContextData().keySet().removeIf(key -> key.startsWith("user.attributes."));

        String claimsJson = storedAuthSession.getAuthNote(DEFERRED_CLAIMS_NOTE);
        if (claimsJson != null) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> claims = JsonSerialization.readValue(claimsJson, Map.class);
                context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
            } catch (Exception e) {
                LOG.warnf("Failed to deserialize claims: %s", e.getMessage());
            }
            storedAuthSession.removeAuthNote(DEFERRED_CLAIMS_NOTE);
        }

        storedAuthSession.removeAuthNote(DEFERRED_IDENTITY_NOTE);

        event.event(EventType.LOGIN);
        Response response = callback.authenticated(context);
        requestObjectStore.removeFlowHandle(session, requestHandle);
        return response;
    }

    public AuthenticationSessionModel resolveExpectedAuthSession(String requestHandle) {
        Map<String, String> signal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + requestHandle);
        if (signal != null) {
            AuthenticationSessionModel authSession =
                    authSessionResolver.resolveFromTokenEntry(signal.get(KEY_ROOT_SESSION_ID), signal.get(KEY_TAB_ID));
            if (authSession != null) {
                return authSession;
            }
        }

        Oid4vpRequestObjectStore.FlowContextEntry flowContext =
                requestObjectStore.resolveFlowHandle(session, requestHandle);
        if (flowContext == null) {
            return null;
        }
        return authSessionResolver.resolveFromTokenEntry(flowContext.rootSessionId(), flowContext.tabId());
    }

    public String buildCompleteAuthUrl(String requestHandle) {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias())
                + "/complete-auth?"
                + Oid4vpConstants.PARAM_REQUEST_HANDLE + "=" + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
    }
}
