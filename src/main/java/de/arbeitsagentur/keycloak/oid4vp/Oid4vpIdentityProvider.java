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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.TrustListProvider;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
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
    private static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 1800;
    private static final int QR_CODE_SIZE = 250;
    private final Oid4vpRedirectFlowService redirectFlowService;
    private final Oid4vpQrCodeService qrCodeService;
    private final Oid4vpCallbackProcessor callbackProcessor;
    private final Oid4vpRequestObjectStore requestObjectStore;

    public Oid4vpIdentityProvider(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        super(session, config);
        this.redirectFlowService = new Oid4vpRedirectFlowService(session, config.getRequestObjectLifespanSeconds());
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
                        config.getIssuerMetadataMaxCacheTtl(),
                        config.isEnforceHaip(),
                        config.getClockSkewSeconds(),
                        config.getKbJwtMaxAgeSeconds(),
                        trustListSigningCerts,
                        config.getTrustListMaxStaleAge(),
                        config.getTrustListLoTEType()));

        RealmModel realm = session.getContext().getRealm();
        int loginTimeoutSeconds = realm != null ? realm.getAccessCodeLifespanLogin() : DEFAULT_LOGIN_TIMEOUT_SECONDS;
        this.requestObjectStore = new Oid4vpRequestObjectStore(Duration.ofSeconds(loginTimeoutSeconds));
    }

    public Oid4vpRedirectFlowService getRedirectFlowService() {
        return redirectFlowService;
    }

    Oid4vpCallbackProcessor getCallbackProcessor() {
        return callbackProcessor;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            AuthenticationSessionModel authSession = request.getAuthenticationSession();

            LoginContext loginContext = initializeLoginContext(request, authSession);

            boolean sameDeviceEnabled = getConfig().isSameDeviceEnabled();
            boolean crossDeviceEnabled = getConfig().isCrossDeviceEnabled();

            RedirectFlowData redirectFlowData =
                    buildRedirectFlowData(request, authSession, loginContext, sameDeviceEnabled, crossDeviceEnabled);

            return buildLoginFormResponse(authSession, redirectFlowData, sameDeviceEnabled, crossDeviceEnabled);

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

    public String buildDcqlQueryFromConfig() {
        return prepareDcqlQueryFromConfig().dcqlQuery();
    }

    public PreparedDcqlQuery prepareDcqlQueryFromConfig() {
        String manual = getConfig().getDcqlQuery();
        if (StringUtil.isNotBlank(manual)) {
            String normalized = DcqlQueryBuilder.normalizeManualQuery(
                    OBJECT_MAPPER,
                    manual,
                    getConfig().getTrustedAuthoritiesMode(),
                    getConfig().getTrustListUrl(),
                    resolveAuthorityKeyIdentifiers());
            return new PreparedDcqlQuery(
                    normalized, DcqlQueryBuilder.extractCredentialTypes(OBJECT_MAPPER, normalized));
        }

        Map<String, CredentialTypeSpec> credentialTypes = DcqlQueryBuilder.aggregateFromMappers(session, getConfig());

        if (!credentialTypes.isEmpty()) {
            String dcqlQuery = DcqlQueryBuilder.fromMapperSpecs(
                            OBJECT_MAPPER,
                            credentialTypes,
                            getConfig().isAllCredentialsRequired(),
                            getConfig().getCredentialSetPurpose(),
                            getConfig().getTrustedAuthoritiesMode(),
                            getConfig().getTrustListUrl(),
                            resolveAuthorityKeyIdentifiers())
                    .build();
            List<String> configuredCredentialTypes = credentialTypes.values().stream()
                    .map(CredentialTypeSpec::type)
                    .filter(StringUtil::isNotBlank)
                    .collect(Collectors.collectingAndThen(Collectors.toCollection(LinkedHashSet::new), List::copyOf));
            return new PreparedDcqlQuery(dcqlQuery, configuredCredentialTypes);
        }

        throw new IdentityBrokerException(
                "No DCQL query configured. Set dcqlQuery or add credential mappers to the OID4VP identity provider.");
    }

    private List<String> resolveAuthorityKeyIdentifiers() {
        if (StringUtil.isBlank(getConfig().getTrustListUrl())
                || getConfig().getTrustedAuthoritiesMode() != Oid4vpTrustedAuthoritiesMode.AKI) {
            return List.of();
        }
        List<X509Certificate> trustListSigningCerts =
                parseTrustListSigningCerts(getConfig().getTrustListSigningCertPem());
        TrustListProvider trustListProvider = new TrustListProvider(
                session,
                getConfig().getTrustListUrl(),
                getConfig().getTrustListMaxCacheTtl(),
                getConfig().getTrustListMaxStaleAge(),
                trustListSigningCerts);
        try {
            List<String> authorityKeyIdentifiers = trustListProvider.getTrustedAuthorityKeyIdentifiers();
            if (authorityKeyIdentifiers.isEmpty()) {
                LOG.warnf(
                        "OID4VP IdP '%s': trusted_authorities type 'aki' is enabled, but no certificate key identifiers could be extracted from trust list %s",
                        getConfig().getAlias(), getConfig().getTrustListUrl());
                return List.of();
            }
            return authorityKeyIdentifiers;
        } catch (Exception e) {
            LOG.warnf(
                    "OID4VP IdP '%s': failed to derive trusted_authorities type 'aki' values from trust list %s: %s",
                    getConfig().getAlias(), getConfig().getTrustListUrl(), e.getMessage());
            return List.of();
        }
    }

    private LoginContext initializeLoginContext(AuthenticationRequest request, AuthenticationSessionModel authSession) {
        String clientId = computeBaseClientId(request);
        String effectiveClientId = computeEffectiveClientId(clientId);

        var uriInfo = request.getUriInfo();
        String requestTabId = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_TAB_ID);
        String clientData = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_CLIENT_DATA);
        String sessionCode = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_SESSION_CODE);
        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String authSessionTabId = authSession.getTabId();
        String flowTabId = StringUtil.isNotBlank(authSessionTabId) ? authSessionTabId : requestTabId;
        String browserTabId = StringUtil.isNotBlank(requestTabId) ? requestTabId : flowTabId;
        if (StringUtil.isNotBlank(requestTabId)
                && StringUtil.isNotBlank(authSessionTabId)
                && !requestTabId.equals(authSessionTabId)) {
            LOG.debugf(
                    "OID4VP login tab_id mismatch, using auth session tab for flow binding and request tab for browser form routing: requestTabId=%s authSessionTabId=%s",
                    requestTabId, authSessionTabId);
        }

        return new LoginContext(
                rootSessionId,
                flowTabId,
                effectiveClientId,
                request.getRedirectUri(),
                browserTabId,
                sessionCode,
                clientData);
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
            LoginContext loginContext,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        if (!sameDeviceEnabled && !crossDeviceEnabled) {
            return RedirectFlowData.EMPTY;
        }

        FlowEntry sameDeviceFlow = null;
        FlowEntry crossDeviceFlow = null;
        String qrCodeBase64 = null;

        if (sameDeviceEnabled) {
            try {
                sameDeviceFlow = createFlowEntry(
                        request,
                        loginContext,
                        Oid4vpConstants.FLOW_SAME_DEVICE,
                        getConfig().getWalletScheme());
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build same-device wallet URL: %s", e.getMessage());
            }
        }

        if (crossDeviceEnabled) {
            try {
                crossDeviceFlow = createFlowEntry(
                        request,
                        loginContext,
                        Oid4vpConstants.FLOW_CROSS_DEVICE,
                        Oid4vpConstants.DEFAULT_WALLET_SCHEME);
                qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceFlow.walletUrl(), QR_CODE_SIZE, QR_CODE_SIZE);
            } catch (Exception e) {
                LOG.errorf(e, "Failed to build cross-device wallet URL: %s", e.getMessage());
            }
        }

        return new RedirectFlowData(sameDeviceFlow, crossDeviceFlow, qrCodeBase64);
    }

    private FlowEntry createFlowEntry(
            AuthenticationRequest request, LoginContext loginContext, String flow, String walletScheme) {
        String requestHandle = UUID.randomUUID().toString();
        String formState = loginContext.flowTabId() + "." + randomState();
        String responseUri = computeVerifierResponseUri();
        String formActionUrl = buildFormActionUrl(
                loginContext.redirectUri(),
                formState,
                loginContext.browserRouteTabId(),
                loginContext.sessionCode(),
                loginContext.clientData());
        requestObjectStore.storeFlowHandle(
                session,
                requestHandle,
                new Oid4vpRequestObjectStore.FlowContextEntry(
                        loginContext.rootSessionId(),
                        loginContext.flowTabId(),
                        loginContext.effectiveClientId(),
                        responseUri,
                        flow));

        URI requestUri = request.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .path("broker")
                .path(getConfig().getAlias())
                .path("endpoint")
                .path("request-object")
                .path(requestHandle)
                .build();
        String walletUrl = redirectFlowService
                .buildWalletAuthorizationUrl(walletScheme, loginContext.effectiveClientId(), requestUri)
                .toString();
        return new FlowEntry(requestHandle, formState, formActionUrl, walletUrl);
    }

    private String computeEffectiveClientId(String clientId) {
        Oid4vpClientIdScheme clientIdScheme = getConfig().getResolvedClientIdScheme();
        return clientIdScheme.computeClientId(clientId, getConfig().getX509CertificatePem());
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
            RedirectFlowData redirectFlowData,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        FlowEntry sameDeviceFlow = redirectFlowData.sameDeviceFlow();
        FlowEntry crossDeviceFlow = redirectFlowData.crossDeviceFlow();
        FlowEntry formFlow = sameDeviceFlow != null ? sameDeviceFlow : crossDeviceFlow;
        String state = formFlow != null ? formFlow.formState() : null;
        String requestHandle = formFlow != null ? formFlow.requestHandle() : null;
        String formActionUrl = formFlow != null ? formFlow.formActionUrl() : null;
        String sameDeviceWalletUrl = redirectFlowData.sameDeviceFlow() != null
                ? redirectFlowData.sameDeviceFlow().walletUrl()
                : null;
        String crossDeviceWalletUrl = redirectFlowData.crossDeviceFlow() != null
                ? redirectFlowData.crossDeviceFlow().walletUrl()
                : null;
        String crossDeviceRequestHandle = crossDeviceFlow != null ? crossDeviceFlow.requestHandle() : null;

        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("state", state)
                .setAttribute("requestHandle", requestHandle)
                .setAttribute("crossDeviceRequestHandle", crossDeviceRequestHandle)
                .setAttribute("currentBrokerAlias", getConfig().getAlias())
                .setAttribute("formActionUrl", formActionUrl)
                .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                .setAttribute("sameDeviceWalletUrl", sameDeviceWalletUrl)
                .setAttribute("crossDeviceWalletUrl", crossDeviceWalletUrl)
                .setAttribute("qrCodeBase64", redirectFlowData.qrCodeBase64())
                .setAttribute("crossDeviceStatusUrl", crossDeviceEnabled ? buildCrossDeviceStatusUrl() : null)
                .setAttribute("crossDevicePollIntervalMs", getConfig().getSsePollIntervalMs())
                .createForm("login-oid4vp-idp.ftl");
    }

    private String computeVerifierResponseUri() {
        return Oid4vpConstants.buildEndpointBaseUrl(
                session.getContext().getUri().getBaseUri(),
                session.getContext().getRealm().getName(),
                getConfig().getAlias());
    }

    private String computeBaseClientId(AuthenticationRequest request) {
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

    record LoginContext(
            String rootSessionId,
            String flowTabId,
            String effectiveClientId,
            String redirectUri,
            String browserRouteTabId,
            String sessionCode,
            String clientData) {}

    record FlowEntry(String requestHandle, String formState, String formActionUrl, String walletUrl) {}

    record RedirectFlowData(FlowEntry sameDeviceFlow, FlowEntry crossDeviceFlow, String qrCodeBase64) {
        static final RedirectFlowData EMPTY = new RedirectFlowData(null, null, null);
    }
}
