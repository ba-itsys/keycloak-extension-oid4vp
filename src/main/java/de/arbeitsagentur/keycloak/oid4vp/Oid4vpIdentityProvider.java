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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.RebuildParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class Oid4vpIdentityProvider extends AbstractIdentityProvider<Oid4vpIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProvider.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    protected final ObjectMapper objectMapper;
    private final Oid4vpRedirectFlowService redirectFlowService;
    private final Oid4vpQrCodeService qrCodeService;
    private final Oid4vpCallbackProcessor callbackProcessor;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final int loginTimeoutSeconds;

    public Oid4vpIdentityProvider(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        super(session, config);
        this.objectMapper = new ObjectMapper();
        this.redirectFlowService = new Oid4vpRedirectFlowService(session, objectMapper);
        this.qrCodeService = new Oid4vpQrCodeService();
        this.callbackProcessor = new Oid4vpCallbackProcessor(
                config,
                config,
                this,
                new VpTokenProcessor(
                        objectMapper,
                        session,
                        config.getTrustListUrl(),
                        config.getStatusListMaxCacheTtl(),
                        config.getTrustListMaxCacheTtl()));

        RealmModel realm = session.getContext().getRealm();
        this.loginTimeoutSeconds = realm != null ? realm.getAccessCodeLifespanLogin() : 1800;
        this.requestObjectStore = new Oid4vpRequestObjectStore(Duration.ofSeconds(loginTimeoutSeconds));
    }

    Oid4vpRedirectFlowService getRedirectFlowService() {
        return redirectFlowService;
    }

    Oid4vpCallbackProcessor getCallbackProcessor() {
        return callbackProcessor;
    }

    Oid4vpRequestObjectStore getRequestObjectStore() {
        return requestObjectStore;
    }

    int getLoginTimeoutSeconds() {
        return loginTimeoutSeconds;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            AuthenticationSessionModel authSession = request.getAuthenticationSession();

            SessionState sessionState = initializeSessionState(request, authSession);

            boolean sameDeviceEnabled = getConfig().isSameDeviceEnabled();
            boolean crossDeviceEnabled = getConfig().isCrossDeviceEnabled();

            RedirectFlowData redirectFlowData =
                    buildRedirectFlowData(request, authSession, sessionState, sameDeviceEnabled, crossDeviceEnabled);

            return buildLoginFormResponse(
                    authSession, sessionState, redirectFlowData, sameDeviceEnabled, crossDeviceEnabled);

        } catch (Exception e) {
            LOG.errorf(e, "Failed to initiate OID4VP login: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to initiate wallet login", e);
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Oid4vpIdentityProviderEndpoint(session, realm, this, callback, event, requestObjectStore);
    }

    protected String buildDcqlQueryFromConfig() {
        String manual = getConfig().getDcqlQuery();
        if (StringUtil.isNotBlank(manual)) {
            return manual;
        }

        Map<String, CredentialTypeSpec> credentialTypes = DcqlQueryBuilder.aggregateFromMappers(session, getConfig());

        if (!credentialTypes.isEmpty()) {
            try {
                return DcqlQueryBuilder.fromMapperSpecs(
                                objectMapper,
                                credentialTypes,
                                getConfig().isAllCredentialsRequired(),
                                getConfig().getCredentialSetPurpose())
                        .build();
            } catch (Exception e) {
                LOG.warnf("Failed to build DCQL from mappers: %s", e.getMessage());
            }
        }

        return new DcqlQueryBuilder(objectMapper).build();
    }

    private SessionState initializeSessionState(AuthenticationRequest request, AuthenticationSessionModel authSession) {
        String tabId = authSession.getTabId();
        String state = tabId + "." + randomState();
        String nonce = randomState();
        String clientId = computeClientId(request);

        authSession.setAuthNote(SESSION_STATE, state);
        authSession.setAuthNote(SESSION_NONCE, nonce);
        authSession.setAuthNote(SESSION_CLIENT_ID, clientId);

        String redirectUri = request.getRedirectUri();
        String responseUri = redirectUri.contains("state=")
                ? redirectUri
                : redirectUri + (redirectUri.contains("?") ? "&" : "?") + "state=" + state;
        authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);

        var uriInfo = request.getUriInfo();
        String sessionTabId = uriInfo.getQueryParameters().getFirst("tab_id");
        String clientData = uriInfo.getQueryParameters().getFirst("client_data");
        String sessionCode = uriInfo.getQueryParameters().getFirst("session_code");
        authSession.setAuthNote(SESSION_TAB_ID, sessionTabId != null ? sessionTabId : "");
        authSession.setAuthNote(SESSION_CLIENT_DATA, clientData != null ? clientData : "");
        authSession.setAuthNote(SESSION_CODE, sessionCode != null ? sessionCode : "");

        String formActionUrl = buildFormActionUrl(redirectUri, state, sessionTabId, sessionCode, clientData);

        return new SessionState(state, nonce, clientId, formActionUrl, redirectUri);
    }

    private String buildFormActionUrl(
            String redirectUri, String state, String tabId, String sessionCode, String clientData) {
        UriBuilder builder = UriBuilder.fromUri(stripQueryParams(redirectUri));
        builder.queryParam("state", state);
        if (StringUtil.isNotBlank(tabId)) {
            builder.queryParam("tab_id", tabId);
        }
        if (StringUtil.isNotBlank(sessionCode)) {
            builder.queryParam("session_code", sessionCode);
        }
        if (StringUtil.isNotBlank(clientData)) {
            builder.queryParam("client_data", clientData);
        }
        return builder.build().toString();
    }

    private RedirectFlowData buildRedirectFlowData(
            AuthenticationRequest request,
            AuthenticationSessionModel authSession,
            SessionState sessionState,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        if (!sameDeviceEnabled && !crossDeviceEnabled) {
            return RedirectFlowData.EMPTY;
        }

        String effectiveClientId = computeEffectiveClientId(sessionState.clientId());
        authSession.setAuthNote(SESSION_EFFECTIVE_CLIENT_ID, effectiveClientId);

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String clientIdForSession =
                authSession.getClient() != null ? authSession.getClient().getClientId() : null;

        String sameDeviceWalletUrl = null;
        String crossDeviceWalletUrl = null;
        String qrCodeBase64 = null;
        boolean indexesStored = false;

        String dcqlQuery = buildDcqlQueryFromConfig();
        String verifierInfo = getConfig().getVerifierInfo();

        if (sameDeviceEnabled) {
            try {
                String sameDeviceResponseUri = stripQueryParams(sessionState.redirectUri());
                URI sameDeviceRequestUri = buildSignStoreRequestObject(
                        request,
                        authSession,
                        dcqlQuery,
                        verifierInfo,
                        sessionState,
                        effectiveClientId,
                        sameDeviceResponseUri,
                        rootSessionId,
                        clientIdForSession,
                        indexesStored);
                indexesStored = true;

                sameDeviceWalletUrl = redirectFlowService
                        .buildWalletAuthorizationUrl(
                                getConfig().getWalletScheme(), effectiveClientId, sameDeviceRequestUri)
                        .toString();
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build same-device request object: %s", e.getMessage());
            }
        }

        if (crossDeviceEnabled) {
            try {
                String crossDeviceResponseUri = stripQueryParams(sessionState.redirectUri()) + "?flow=cross_device";
                URI crossDeviceRequestUri = buildSignStoreRequestObject(
                        request,
                        authSession,
                        dcqlQuery,
                        verifierInfo,
                        sessionState,
                        effectiveClientId,
                        crossDeviceResponseUri,
                        rootSessionId,
                        clientIdForSession,
                        indexesStored);

                crossDeviceWalletUrl = redirectFlowService
                        .buildWalletAuthorizationUrl("openid4vp://", effectiveClientId, crossDeviceRequestUri)
                        .toString();
                qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceWalletUrl, 250, 250);
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build cross-device request object: %s", e.getMessage());
            }
        }

        return new RedirectFlowData(sameDeviceWalletUrl, crossDeviceWalletUrl, qrCodeBase64);
    }

    private URI buildSignStoreRequestObject(
            AuthenticationRequest request,
            AuthenticationSessionModel authSession,
            String dcqlQuery,
            String verifierInfo,
            SessionState sessionState,
            String effectiveClientId,
            String responseUri,
            String rootSessionId,
            String clientIdForSession,
            boolean skipIndexes) {

        SignedRequestObject signedRequest = redirectFlowService.buildSignedRequestObject(
                dcqlQuery,
                verifierInfo,
                effectiveClientId,
                getConfig().getClientIdScheme(),
                responseUri,
                sessionState.state(),
                sessionState.nonce(),
                getConfig().getX509CertificatePem(),
                getConfig().getX509SigningKeyJwk(),
                null,
                getConfig().isEnforceHaip(),
                loginTimeoutSeconds);

        authSession.setAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI, responseUri);
        authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
        if (signedRequest.encryptionKeyJson() != null) {
            authSession.setAuthNote(SESSION_ENCRYPTION_KEY, signedRequest.encryptionKeyJson());
        }

        String encryptionPublicKeyJson = extractEncryptionPublicKey(signedRequest.encryptionKeyJson());

        RebuildParams rebuildParams = new RebuildParams(
                effectiveClientId,
                getConfig().getClientIdScheme(),
                responseUri,
                dcqlQuery,
                getConfig().getX509CertificatePem(),
                getConfig().getX509SigningKeyJwk(),
                encryptionPublicKeyJson,
                verifierInfo);

        String requestObjectId = requestObjectStore.store(
                session,
                signedRequest.jwt(),
                signedRequest.encryptionKeyJson(),
                sessionState.state(),
                sessionState.nonce(),
                rootSessionId,
                clientIdForSession,
                rebuildParams,
                skipIndexes);

        return request.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .path("broker")
                .path(getConfig().getAlias())
                .path("endpoint")
                .path("request-object")
                .path(requestObjectId)
                .build();
    }

    private String computeEffectiveClientId(String clientId) {
        String clientIdScheme = getConfig().getClientIdScheme();
        String x509Pem = getConfig().getX509CertificatePem();
        if ("x509_san_dns".equalsIgnoreCase(clientIdScheme) && StringUtil.isNotBlank(x509Pem)) {
            return redirectFlowService.computeX509SanDnsClientId(x509Pem);
        } else if ("x509_hash".equalsIgnoreCase(clientIdScheme) && StringUtil.isNotBlank(x509Pem)) {
            return redirectFlowService.computeX509HashClientId(x509Pem);
        }
        return clientId;
    }

    private String extractEncryptionPublicKey(String encryptionKeyJson) {
        if (encryptionKeyJson == null) {
            return null;
        }
        try {
            var encKey = ECKey.parse(encryptionKeyJson);
            return encKey.toPublicJWK().toJSONString();
        } catch (Exception e) {
            LOG.warnf("Failed to extract public key: %s", e.getMessage());
            return null;
        }
    }

    private String buildCrossDeviceStatusUrl() {
        String baseUri = session.getContext().getUri().getBaseUri().toString();
        if (!baseUri.endsWith("/")) {
            baseUri += "/";
        }
        return baseUri + "realms/" + session.getContext().getRealm().getName() + "/broker/"
                + getConfig().getAlias() + "/endpoint/cross-device/status";
    }

    private Response buildLoginFormResponse(
            AuthenticationSessionModel authSession,
            SessionState sessionState,
            RedirectFlowData redirectFlowData,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("state", sessionState.state())
                .setAttribute("nonce", sessionState.nonce())
                .setAttribute("formActionUrl", sessionState.formActionUrl())
                .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                .setAttribute("sameDeviceWalletUrl", redirectFlowData.sameDeviceWalletUrl())
                .setAttribute("crossDeviceWalletUrl", redirectFlowData.crossDeviceWalletUrl())
                .setAttribute("qrCodeBase64", redirectFlowData.qrCodeBase64())
                .setAttribute(
                        "crossDeviceStatusUrl",
                        (crossDeviceEnabled || sameDeviceEnabled) ? buildCrossDeviceStatusUrl() : null)
                .createForm("login-oid4vp-idp.ftl");
    }

    private String computeClientId(AuthenticationRequest request) {
        URI realmBase = request.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .build();
        String value = realmBase.toString();
        return value.endsWith("/") ? value : value + "/";
    }

    private String stripQueryParams(String uri) {
        if (uri == null) {
            return null;
        }
        int queryIndex = uri.indexOf('?');
        return queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;
    }

    private static String randomState() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    record SessionState(String state, String nonce, String clientId, String formActionUrl, String redirectUri) {}

    record RedirectFlowData(String sameDeviceWalletUrl, String crossDeviceWalletUrl, String qrCodeBase64) {
        static final RedirectFlowData EMPTY = new RedirectFlowData(null, null, null);
    }
}
