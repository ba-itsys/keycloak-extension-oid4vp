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

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

class Oid4vpDirectPostService {

    private static final Logger LOG = Logger.getLogger(Oid4vpDirectPostService.class);

    static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";
    private final long crossDeviceCompleteTtlSeconds;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpIdentityProviderConfig config;
    private final Oid4vpAuthSessionResolver authSessionResolver;
    private final Oid4vpRequestObjectStore requestObjectStore;

    Oid4vpDirectPostService(
            KeycloakSession session,
            RealmModel realm,
            Oid4vpIdentityProviderConfig config,
            Oid4vpAuthSessionResolver authSessionResolver,
            Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.config = config;
        this.authSessionResolver = authSessionResolver;
        this.requestObjectStore = requestObjectStore;
        this.crossDeviceCompleteTtlSeconds = config.getCrossDeviceCompleteTtlSeconds();
    }

    Response storeAndSignal(AuthenticationSessionModel authSession, String state, BrokeredIdentityContext context) {

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String tabId = authSession.getTabId();

        context.setAuthenticationSession(authSession);
        SerializedBrokeredIdentityContext serialized = SerializedBrokeredIdentityContext.serialize(context);
        serialized.saveToAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);

        @SuppressWarnings("unchecked")
        Map<String, Object> claims =
                (Map<String, Object>) context.getContextData().get("oid4vp_claims");
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
        deferredSignal.put("root_session_id", rootSessionId != null ? rootSessionId : "");
        deferredSignal.put("tab_id", tabId != null ? tabId : "");
        session.singleUseObjects().put(DEFERRED_AUTH_PREFIX + state, crossDeviceCompleteTtlSeconds, deferredSignal);

        Map<String, String> completeEntry = new HashMap<>();
        completeEntry.put("complete_auth_url", completeAuthUrl);
        session.singleUseObjects()
                .put(CROSS_DEVICE_COMPLETE_PREFIX + state, crossDeviceCompleteTtlSeconds, completeEntry);

        return jsonRedirectResponse(completeAuthUrl);
    }

    Response completeAuth(String state, AbstractIdentityProvider.AuthenticationCallback callback, EventBuilder event) {

        Map<String, String> signal = session.singleUseObjects().get(DEFERRED_AUTH_PREFIX + state);
        if (signal == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Authentication data not found. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        String rootSessionId = signal.get("root_session_id");
        String tabId = signal.get("tab_id");

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
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Authentication session not found. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);
        if (serializedCtx == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Authentication data not found. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
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
                context.getContextData().put("oid4vp_claims", claims);
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

    Response handleCompletion(String token, String source) {
        Map<String, String> entry = session.singleUseObjects().get(CROSS_DEVICE_COMPLETE_PREFIX + token);
        if (entry == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Session expired. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        String redirectUri = entry.get("redirect_uri");
        String rootSessionId = entry.get("root_session_id");

        if (StringUtil.isBlank(redirectUri)) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Authentication failed. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!redirectUri.startsWith(baseUri)) {
            LOG.warnf("Redirect URI does not start with base URI: %s", redirectUri);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid redirect URI.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        if (StringUtil.isNotBlank(rootSessionId)) {
            try {
                new AuthenticationSessionManager(session).setAuthSessionCookie(rootSessionId);
            } catch (Exception e) {
                LOG.warnf("Failed to set AUTH_SESSION_ID cookie: %s", e.getMessage());
            }
        }

        if ("wallet".equals(source)) {
            String html = "<!DOCTYPE html><html><head><title>Login Complete</title>"
                    + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                    + "<style>body{font-family:sans-serif;display:flex;justify-content:center;"
                    + "align-items:center;min-height:100vh;margin:0;background:#f5f5f5;}"
                    + ".card{text-align:center;padding:40px;background:white;border-radius:8px;"
                    + "box-shadow:0 2px 8px rgba(0,0,0,0.1);}"
                    + "h1{color:#333;margin-bottom:10px;}p{color:#666;}</style></head>"
                    + "<body><div class=\"card\"><h1>Login Complete</h1>"
                    + "<p>Authentication successful. You can close this tab.</p></div></body></html>";
            return Response.ok(html).type(MediaType.TEXT_HTML).build();
        }

        return Response.status(Response.Status.FOUND)
                .location(URI.create(redirectUri))
                .build();
    }

    String buildCompleteAuthUrl(String state) {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + realm.getName() + "/broker/" + config.getAlias() + "/endpoint/complete-auth?state="
                + java.net.URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    private Response jsonRedirectResponse(String redirectUri) {
        try {
            String json = JsonSerialization.writeValueAsString(Map.of("redirect_uri", redirectUri));
            return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            return Response.ok("{\"redirect_uri\":\"\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
