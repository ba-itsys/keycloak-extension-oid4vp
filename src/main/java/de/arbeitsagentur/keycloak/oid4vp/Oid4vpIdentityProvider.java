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
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Keycloak Identity Provider implementation for OpenID for Verifiable Presentations (OID4VP) 1.0.
 *
 * <p>Enables Keycloak to act as an OID4VP verifier, accepting Verifiable Credentials from
 * digital wallets as a login mechanism. Supports same-device (wallet redirect) and cross-device
 * (QR code scanning) flows. The {@link #performLogin} method renders the login page with wallet
 * URLs and QR codes, while {@link #callback} returns the JAX-RS endpoint that handles wallet responses.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</a>
 */
public class Oid4vpIdentityProvider extends AbstractIdentityProvider<Oid4vpIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProvider.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final Oid4vpRedirectFlowService redirectFlowService;
    private final Oid4vpQrCodeService qrCodeService;
    private final Oid4vpCallbackProcessor callbackProcessor;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final int loginTimeoutSeconds;

    public Oid4vpIdentityProvider(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        super(session, config);
        this.redirectFlowService = new Oid4vpRedirectFlowService(session);
        this.qrCodeService = new Oid4vpQrCodeService();

        List<X509Certificate> trustListSigningCerts = parseTrustListSigningCerts(config.getTrustListSigningCertPem());

        this.callbackProcessor = new Oid4vpCallbackProcessor(
                config,
                config,
                this,
                new VpTokenProcessor(
                        OBJECT_MAPPER,
                        session,
                        config.getTrustListUrl(),
                        config.getStatusListMaxCacheTtl(),
                        config.getTrustListMaxCacheTtl(),
                        config.getClockSkewSeconds(),
                        config.getKbJwtMaxAgeSeconds(),
                        trustListSigningCerts));

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

    String buildDcqlQueryFromConfig() {
        String manual = getConfig().getDcqlQuery();
        if (StringUtil.isNotBlank(manual)) {
            return manual;
        }

        Map<String, CredentialTypeSpec> credentialTypes = DcqlQueryBuilder.aggregateFromMappers(session, getConfig());

        if (!credentialTypes.isEmpty()) {
            String trustListUrl =
                    getConfig().isIncludeTrustedAuthorities() ? getConfig().getTrustListUrl() : null;
            return DcqlQueryBuilder.fromMapperSpecs(
                            OBJECT_MAPPER,
                            credentialTypes,
                            getConfig().isAllCredentialsRequired(),
                            getConfig().getCredentialSetPurpose(),
                            trustListUrl)
                    .build();
        }

        throw new IdentityBrokerException(
                "No DCQL query configured. Set dcqlQuery or add credential mappers to the OID4VP identity provider.");
    }

    private SessionState initializeSessionState(AuthenticationRequest request, AuthenticationSessionModel authSession) {
        String tabId = authSession.getTabId();
        String state = tabId + "." + randomState();
        String clientId = computeClientId(request);

        authSession.setAuthNote(SESSION_STATE, state);
        authSession.setAuthNote(SESSION_CLIENT_ID, clientId);

        String effectiveClientId = computeEffectiveClientId(clientId);
        authSession.setAuthNote(SESSION_EFFECTIVE_CLIENT_ID, effectiveClientId);

        String redirectUri = request.getRedirectUri();
        String responseUri = redirectUri.contains("state=")
                ? redirectUri
                : redirectUri + (redirectUri.contains("?") ? "&" : "?") + "state=" + state;
        authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);

        var uriInfo = request.getUriInfo();
        String sessionTabId = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_TAB_ID);
        String clientData = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_CLIENT_DATA);
        String sessionCode = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_SESSION_CODE);

        String formActionUrl = buildFormActionUrl(redirectUri, state, sessionTabId, sessionCode, clientData);

        return new SessionState(state, effectiveClientId, formActionUrl);
    }

    private String buildFormActionUrl(
            String redirectUri, String state, String tabId, String sessionCode, String clientData) {
        int queryIndex = redirectUri != null ? redirectUri.indexOf('?') : -1;
        String baseUri = queryIndex >= 0 ? redirectUri.substring(0, queryIndex) : redirectUri;
        UriBuilder builder = UriBuilder.fromUri(baseUri);
        builder.queryParam(OAuth2Constants.STATE, state);
        if (StringUtil.isNotBlank(tabId)) {
            builder.queryParam(Oid4vpConstants.PARAM_TAB_ID, tabId);
        }
        if (StringUtil.isNotBlank(sessionCode)) {
            builder.queryParam(Oid4vpConstants.PARAM_SESSION_CODE, sessionCode);
        }
        if (StringUtil.isNotBlank(clientData)) {
            builder.queryParam(Oid4vpConstants.PARAM_CLIENT_DATA, clientData);
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

        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;

        String requestHandle = UUID.randomUUID().toString();
        requestObjectStore.storeRequestHandle(session, requestHandle, rootSessionId, authSession.getTabId());
        requestObjectStore.storeStateIndex(session, sessionState.state(), rootSessionId, authSession.getTabId());

        URI requestObjectBaseUri = request.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .path("broker")
                .path(getConfig().getAlias())
                .path("endpoint")
                .path("request-object")
                .path(requestHandle)
                .build();

        String sameDeviceWalletUrl = null;
        String crossDeviceWalletUrl = null;
        String qrCodeBase64 = null;

        if (sameDeviceEnabled) {
            try {
                URI sameDeviceRequestUri = UriBuilder.fromUri(requestObjectBaseUri)
                        .queryParam(Oid4vpConstants.FLOW_PARAM, Oid4vpConstants.FLOW_SAME_DEVICE)
                        .build();
                sameDeviceWalletUrl = redirectFlowService
                        .buildWalletAuthorizationUrl(
                                getConfig().getWalletScheme(), sessionState.effectiveClientId(), sameDeviceRequestUri)
                        .toString();
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build same-device wallet URL: %s", e.getMessage());
            }
        }

        if (crossDeviceEnabled) {
            try {
                URI crossDeviceRequestUri = UriBuilder.fromUri(requestObjectBaseUri)
                        .queryParam(Oid4vpConstants.FLOW_PARAM, Oid4vpConstants.FLOW_CROSS_DEVICE)
                        .build();
                crossDeviceWalletUrl = redirectFlowService
                        .buildWalletAuthorizationUrl(
                                Oid4vpConstants.DEFAULT_WALLET_SCHEME,
                                sessionState.effectiveClientId(),
                                crossDeviceRequestUri)
                        .toString();
                qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceWalletUrl, 250, 250);
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build cross-device wallet URL: %s", e.getMessage());
            }
        }

        return new RedirectFlowData(sameDeviceWalletUrl, crossDeviceWalletUrl, qrCodeBase64);
    }

    private String computeEffectiveClientId(String clientId) {
        String clientIdScheme = getConfig().getClientIdScheme();
        String x509Pem = getConfig().getX509CertificatePem();
        if (Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS.equalsIgnoreCase(clientIdScheme)
                && StringUtil.isNotBlank(x509Pem)) {
            return redirectFlowService.computeX509SanDnsClientId(x509Pem);
        } else if (Oid4vpConstants.CLIENT_ID_SCHEME_X509_HASH.equalsIgnoreCase(clientIdScheme)
                && StringUtil.isNotBlank(x509Pem)) {
            return redirectFlowService.computeX509HashClientId(x509Pem);
        }
        return clientId;
    }

    private String buildCrossDeviceStatusUrl() {
        return Oid4vpConstants.buildEndpointBaseUrl(
                        session.getContext().getUri().getBaseUri(),
                        session.getContext().getRealm().getName(),
                        getConfig().getAlias())
                + "/cross-device/status";
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
                .setAttribute("formActionUrl", sessionState.formActionUrl())
                .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                .setAttribute("sameDeviceWalletUrl", redirectFlowData.sameDeviceWalletUrl())
                .setAttribute("crossDeviceWalletUrl", redirectFlowData.crossDeviceWalletUrl())
                .setAttribute("qrCodeBase64", redirectFlowData.qrCodeBase64())
                .setAttribute("crossDeviceStatusUrl", crossDeviceEnabled ? buildCrossDeviceStatusUrl() : null)
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

    private static List<X509Certificate> parseTrustListSigningCerts(String pem) {
        if (pem == null || pem.isBlank()) {
            return null;
        }
        try {
            X509Certificate[] certs = PemUtils.decodeCertificates(pem);
            if (certs != null && certs.length > 0) {
                return List.of(certs);
            }
        } catch (Exception e) {
            LOG.warnf("Failed to parse trust list signing certificate(s): %s", e.getMessage());
        }
        return null;
    }

    private static String randomState() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    record SessionState(String state, String effectiveClientId, String formActionUrl) {}

    record RedirectFlowData(String sameDeviceWalletUrl, String crossDeviceWalletUrl, String qrCodeBase64) {
        static final RedirectFlowData EMPTY = new RedirectFlowData(null, null, null);
    }
}
