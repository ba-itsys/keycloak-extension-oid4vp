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
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class Oid4vpDirectPostService {

    private static final Logger LOG = Logger.getLogger(Oid4vpDirectPostService.class);

    public static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    public static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    public static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    public static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";

    static final String KEY_ROOT_SESSION_ID = "root_session_id";
    static final String KEY_TAB_ID = "tab_id";
    static final String KEY_COMPLETE_AUTH_URL = "complete_auth_url";

    private final long crossDeviceCompleteTtlSeconds;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpConfigProvider config;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpRequestObjectStore requestObjectStore;

    public Oid4vpDirectPostService(
            KeycloakSession session,
            RealmModel realm,
            Oid4vpConfigProvider config,
            Oid4vpAuthSessionResolver authSessionResolver,
            Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.config = config;
        this.authSessionResolver = authSessionResolver;
        this.requestObjectStore = requestObjectStore;
        this.crossDeviceCompleteTtlSeconds = config.getCrossDeviceCompleteTtlSeconds();
    }

    public Response storeAndSignal(
            AuthenticationSessionModel authSession,
            String state,
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

        String completeAuthUrl = buildCompleteAuthUrl(state);
        Map<String, String> deferredSignal = new HashMap<>();
        deferredSignal.put(KEY_ROOT_SESSION_ID, rootSessionId != null ? rootSessionId : "");
        deferredSignal.put(KEY_TAB_ID, tabId != null ? tabId : "");
        session.singleUseObjects().put(DEFERRED_AUTH_PREFIX + state, crossDeviceCompleteTtlSeconds, deferredSignal);

        Map<String, String> completeEntry = new HashMap<>();
        completeEntry.put(KEY_COMPLETE_AUTH_URL, completeAuthUrl);
        session.singleUseObjects()
                .put(CROSS_DEVICE_COMPLETE_PREFIX + state, crossDeviceCompleteTtlSeconds, completeEntry);

        if (isCrossDevice) {
            return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
        }
        return jsonRedirectResponse(completeAuthUrl);
    }

    public Response completeAuth(
            String state, AbstractIdentityProvider.AuthenticationCallback callback, EventBuilder event) {

        Map<String, String> signal = session.singleUseObjects().remove(DEFERRED_AUTH_PREFIX + state);
        if (signal == null) {
            return ErrorPage.error(
                    session,
                    null,
                    Response.Status.BAD_REQUEST,
                    "Authentication session expired. Please try logging in again.");
        }

        String rootSessionId = signal.get(KEY_ROOT_SESSION_ID);
        String tabId = signal.get(KEY_TAB_ID);

        if (rootSessionId != null) {
            try {
                new AuthenticationSessionManager(session).setAuthSessionCookie(rootSessionId);
            } catch (Exception e) {
                LOG.warnf("Failed to set AUTH_SESSION_ID cookie: %s", e.getMessage());
            }
        }

        AuthenticationSessionModel authSession = null;
        if (rootSessionId != null) {
            RootAuthenticationSessionModel rootSession =
                    session.authenticationSessions().getRootAuthenticationSession(realm, rootSessionId);
            if (rootSession != null && tabId != null) {
                authSession = authSessionResolver.findAuthSessionInRoot(rootSession, tabId);
            }
        }
        if (authSession == null) {
            return ErrorPage.error(
                    session,
                    null,
                    Response.Status.BAD_REQUEST,
                    "Authentication session expired. Please try logging in again.");
        }

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);
        if (serializedCtx == null) {
            return ErrorPage.error(
                    session,
                    authSession,
                    Response.Status.BAD_REQUEST,
                    "Authentication data not found. Please try logging in again.");
        }

        session.getContext().setAuthenticationSession(authSession);
        session.getContext().setClient(authSession.getClient());

        BrokeredIdentityContext context = serializedCtx.deserialize(session, authSession);
        context.setAuthenticationSession(authSession);
        context.getContextData().keySet().removeIf(key -> key.startsWith("user.attributes."));

        String claimsJson = authSession.getAuthNote(DEFERRED_CLAIMS_NOTE);
        if (claimsJson != null) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> claims = JsonSerialization.readValue(claimsJson, Map.class);
                context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
            } catch (Exception e) {
                LOG.warnf("Failed to deserialize claims: %s", e.getMessage());
            }
            authSession.removeAuthNote(DEFERRED_CLAIMS_NOTE);
        }

        authSession.removeAuthNote(DEFERRED_IDENTITY_NOTE);

        event.event(EventType.LOGIN);
        Response response = callback.authenticated(context);

        try {
            requestObjectStore.removeByState(session, state);
        } catch (Exception e) {
            LOG.warnf("Failed to clean up request objects: %s", e.getMessage());
        }

        return response;
    }

    public Response handleCompletion(String token) {
        Map<String, String> entry = session.singleUseObjects().remove(CROSS_DEVICE_COMPLETE_PREFIX + token);
        if (entry == null) {
            return ErrorPage.error(
                    session, null, Response.Status.BAD_REQUEST, "Session expired. Please try logging in again.");
        }

        String redirectUri = entry.get(KEY_COMPLETE_AUTH_URL);

        if (StringUtil.isBlank(redirectUri)) {
            return ErrorPage.error(
                    session, null, Response.Status.INTERNAL_SERVER_ERROR, "Authentication failed. Please try again.");
        }

        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!redirectUri.startsWith(baseUri)) {
            LOG.warnf("Redirect URI does not start with base URI: %s", redirectUri);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "Invalid redirect.");
        }

        return Response.status(Response.Status.FOUND)
                .location(URI.create(redirectUri))
                .build();
    }

    public String buildCompleteAuthUrl(String state) {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias())
                + "/complete-auth?"
                + OAuth2Constants.STATE + "=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
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
}
