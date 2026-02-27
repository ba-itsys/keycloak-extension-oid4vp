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

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProvider.*;

import com.nimbusds.jose.JWEObject;
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
import jakarta.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

@Vetoed
@Path("")
public class Oid4vpIdentityProviderEndpoint {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderEndpoint.class);
    static final String CROSS_DEVICE_COMPLETE_PREFIX = "oid4vp_complete:";
    private static final String DEFERRED_AUTH_PREFIX = "oid4vp_deferred:";
    private static final String DEFERRED_IDENTITY_NOTE = "OID4VP_DEFERRED_IDENTITY";
    private static final String DEFERRED_CLAIMS_NOTE = "OID4VP_DEFERRED_CLAIMS";
    private static final long CROSS_DEVICE_COMPLETE_TTL_SECONDS = 300;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpIdentityProvider provider;
    private final AbstractIdentityProvider.AuthenticationCallback callback;
    private final EventBuilder event;
    private final Oid4vpRequestObjectStore requestObjectStore;

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
            authSession = resolveAuthSessionFromStore(state, null);
        }

        if (error != null && !error.isBlank()) {
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
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"" + jsonEscape(e.getMessage()) + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
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
        String state = queryState != null && !queryState.isBlank() ? queryState : formState;
        boolean hasError = error != null && !error.isBlank();
        boolean hadEncryptedResponse = encryptedResponse != null && !encryptedResponse.isBlank();

        String preDecryptedMdocGeneratedNonce = null;
        if ((state == null || state.isBlank()) && encryptedResponse != null && !encryptedResponse.isBlank()) {
            try {
                JWEObject jwe = JWEObject.parse(encryptedResponse);
                String kid = jwe.getHeader().getKeyID();
                if (kid != null) {
                    Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolveByKid(session, kid);
                    if (stored != null && stored.encryptionKeyJson() != null) {
                        state = stored.state();
                        com.nimbusds.jose.jwk.ECKey decryptionKey =
                                com.nimbusds.jose.jwk.ECKey.parse(stored.encryptionKeyJson());
                        jwe.decrypt(new com.nimbusds.jose.crypto.ECDHDecrypter(decryptionKey));
                        String payload = jwe.getPayload().toString();

                        @SuppressWarnings("unchecked")
                        Map<String, Object> payloadMap = provider.objectMapper.readValue(payload, Map.class);

                        com.nimbusds.jose.util.Base64URL apu = jwe.getHeader().getAgreementPartyUInfo();
                        if (apu != null) {
                            preDecryptedMdocGeneratedNonce = apu.toString();
                        }

                        if (payloadMap.containsKey("vp_token")) {
                            Object vpTokenObj = payloadMap.get("vp_token");
                            vpToken = vpTokenObj instanceof String
                                    ? (String) vpTokenObj
                                    : provider.objectMapper.writeValueAsString(vpTokenObj);
                            encryptedResponse = null;
                        }
                        if (payloadMap.containsKey("error")) {
                            error = payloadMap.get("error").toString();
                            errorDescription = payloadMap.containsKey("error_description")
                                    ? payloadMap.get("error_description").toString()
                                    : null;
                            hasError = true;
                        }
                    }
                }
            } catch (Exception e) {
                LOG.warnf("JWE kid lookup/decrypt failed: %s", e.getMessage());
            }
        }

        boolean isDirectPostFlow = isCrossDeviceFlow;
        AuthenticationSessionModel authSession = resolveAuthSession(state, tabId, sessionCode, clientData);
        if (authSession == null && state != null) {
            authSession = resolveAuthSessionFromStore(state, null);
            if (authSession != null) {
                isDirectPostFlow = true;
            }
        }

        if (authSession == null) {
            event.event(EventType.LOGIN_ERROR).error(Errors.SESSION_EXPIRED);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"session_expired\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
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
        if (id == null || id.isBlank()) {
            return badRequest("Missing request object id");
        }

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            return notFound("Request object not found or expired");
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

        if (id == null || id.isBlank()) {
            return badRequest("Missing request object id");
        }

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolve(session, id);
        if (stored == null) {
            return notFound("Request object not found or expired");
        }

        if (walletNonce != null && !walletNonce.isBlank() && stored.rebuildParams() != null) {
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
        if (state == null || state.isBlank()) {
            return badRequest("Missing state parameter");
        }

        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        String realmName = realm.getName();

        StreamingOutput stream = output -> {
            try {
                for (int i = 0; i < 300; i++) {
                    try (KeycloakSession pollingSession = sessionFactory.create()) {
                        pollingSession.getTransactionManager().begin();
                        try {
                            RealmModel pollingRealm = pollingSession.realms().getRealmByName(realmName);
                            if (pollingRealm == null) {
                                writeSseEvent(output, "error", "{\"error\":\"realm_not_found\"}");
                                return;
                            }
                            SingleUseObjectProvider store = pollingSession.singleUseObjects();
                            Map<String, String> entry = store.get(CROSS_DEVICE_COMPLETE_PREFIX + state);
                            if (entry != null) {
                                String completeAuthUrl = entry.get("complete_auth_url");
                                if (completeAuthUrl != null) {
                                    writeSseEvent(output, "complete", "{\"redirect_uri\":\"" + completeAuthUrl + "\"}");
                                    pollingSession.getTransactionManager().commit();
                                    return;
                                }
                            }
                            pollingSession.getTransactionManager().commit();
                        } catch (Exception e) {
                            pollingSession.getTransactionManager().rollback();
                        }
                    }

                    if (i % 5 == 0) {
                        writeSseEvent(output, "ping", "{}");
                    }

                    Thread.sleep(1000);
                }

                writeSseEvent(output, "timeout", "{\"error\":\"timeout\"}");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // Client disconnected
            }
        };

        return Response.ok(stream)
                .type("text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .header("X-Accel-Buffering", "no")
                .build();
    }

    @GET
    @Path("/cross-device/complete")
    public Response crossDeviceComplete(@QueryParam("token") String token, @QueryParam("source") String source) {
        if (token == null || token.isBlank()) {
            return badRequest("Missing token parameter");
        }

        Map<String, String> entry = session.singleUseObjects().get(CROSS_DEVICE_COMPLETE_PREFIX + token);
        if (entry == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Session expired. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        String redirectUri = entry.get("redirect_uri");
        String rootSessionId = entry.get("root_session_id");

        if (redirectUri == null || redirectUri.isBlank()) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Authentication failed. Please try again.")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        if (rootSessionId != null && !rootSessionId.isBlank()) {
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

    @GET
    @Path("/complete-auth")
    public Response completeAuth(@QueryParam("state") String state) {
        if (state == null || state.isBlank()) {
            return badRequest("Missing state parameter");
        }

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
                authSession = findAuthSessionInRoot(rootSession, tabId);
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
                Map<String, Object> claims = org.keycloak.util.JsonSerialization.readValue(claimsJson, Map.class);
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
            BrokeredIdentityContext context =
                    provider.processCallback(authSession, state, vpToken, encryptedResponse, error, errorDescription);

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
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"" + jsonEscape(e.getMessage()) + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    private Response handleDirectPostAuthentication(
            AuthenticationSessionModel authSession,
            String state,
            BrokeredIdentityContext context,
            boolean isCrossDeviceFlow) {

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String tabId = authSession.getTabId();

        // Store identity in auth session for deferred browser-side completion
        context.setAuthenticationSession(authSession);
        SerializedBrokeredIdentityContext serialized = SerializedBrokeredIdentityContext.serialize(context);
        serialized.saveToAuthenticationSession(authSession, DEFERRED_IDENTITY_NOTE);

        // Store claims separately (they don't survive contextData serialization)
        @SuppressWarnings("unchecked")
        Map<String, Object> claims =
                (Map<String, Object>) context.getContextData().get("oid4vp_claims");
        if (claims != null) {
            try {
                String claimsJson = org.keycloak.util.JsonSerialization.writeValueAsString(claims);
                authSession.setAuthNote(DEFERRED_CLAIMS_NOTE, claimsJson);
            } catch (Exception e) {
                LOG.warnf("Failed to serialize claims: %s", e.getMessage());
            }
        }

        // Store deferred auth signal
        String completeAuthUrl = buildCompleteAuthUrl(state);
        Map<String, String> deferredSignal = new HashMap<>();
        deferredSignal.put("root_session_id", rootSessionId != null ? rootSessionId : "");
        deferredSignal.put("tab_id", tabId != null ? tabId : "");
        session.singleUseObjects().put(DEFERRED_AUTH_PREFIX + state, CROSS_DEVICE_COMPLETE_TTL_SECONDS, deferredSignal);

        // Signal SSE listeners
        Map<String, String> completeEntry = new HashMap<>();
        completeEntry.put("complete_auth_url", completeAuthUrl);
        session.singleUseObjects()
                .put(CROSS_DEVICE_COMPLETE_PREFIX + state, CROSS_DEVICE_COMPLETE_TTL_SECONDS, completeEntry);

        return jsonRedirectResponse(completeAuthUrl);
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
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"" + jsonEscape(error) + "\""
                            + (errorDescription != null
                                    ? ",\"error_description\":\"" + jsonEscape(errorDescription) + "\""
                                    : "")
                            + "}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String message = error + (errorDescription != null ? ": " + errorDescription : "");
        return callback.error(getIdpModel(), message);
    }

    private Response rebuildRequestObjectWithWalletNonce(
            Oid4vpRequestObjectStore.StoredRequestObject stored, String walletNonce) {
        try {
            Oid4vpRedirectFlowService.SignedRequestObject rebuilt = provider.getRedirectFlowService()
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
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    private AuthenticationSessionModel resolveAuthSession(
            String state, String tabId, String sessionCode, String clientData) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession != null) {
            return authSession;
        }
        if (tabId != null && !tabId.isBlank()) {
            try {
                return callback.getAndVerifyAuthenticationSession(state);
            } catch (Exception e) {
                LOG.debugf("Failed to resolve auth session via callback: %s", e.getMessage());
            }
        }
        return null;
    }

    private AuthenticationSessionModel resolveAuthSessionFromStore(String state, String tabIdHint) {
        if (state == null) return null;

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolveByState(session, state);
        if (stored == null || stored.rootSessionId() == null) {
            return null;
        }

        RootAuthenticationSessionModel rootSession =
                session.authenticationSessions().getRootAuthenticationSession(realm, stored.rootSessionId());
        if (rootSession == null) {
            return null;
        }

        // Extract tabId from state format: {tabId}.{randomData}
        String tabId = tabIdHint;
        if (tabId == null && state.contains(".")) {
            tabId = state.substring(0, state.indexOf('.'));
        }

        return tabId != null ? findAuthSessionInRoot(rootSession, tabId) : null;
    }

    private AuthenticationSessionModel findAuthSessionInRoot(RootAuthenticationSessionModel rootSession, String tabId) {
        for (Map.Entry<String, AuthenticationSessionModel> entry :
                rootSession.getAuthenticationSessions().entrySet()) {
            if (entry.getKey().equals(tabId)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private String buildCompleteAuthUrl(String state) {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + realm.getName() + "/broker/"
                + provider.getConfig().getAlias() + "/endpoint/complete-auth?state="
                + java.net.URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    private String buildBridgeUrl(String bridgeToken) {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + realm.getName() + "/broker/"
                + provider.getConfig().getAlias() + "/endpoint/cross-device/complete?token="
                + java.net.URLEncoder.encode(bridgeToken, StandardCharsets.UTF_8);
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

    private void writeSseEvent(OutputStream output, String eventType, String data) throws IOException {
        output.write(("event: " + eventType + "\n").getBytes(StandardCharsets.UTF_8));
        output.write(("data: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
        output.flush();
    }

    private Response jsonRedirectResponse(String redirectUri) {
        return Response.ok("{\"redirect_uri\":\"" + jsonEscape(redirectUri) + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private Response badRequest(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"invalid_request\",\"error_description\":\"" + jsonEscape(message) + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private Response notFound(String message) {
        return Response.status(Response.Status.NOT_FOUND)
                .entity("{\"error\":\"not_found\",\"error_description\":\"" + jsonEscape(message) + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private String jsonEscape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
