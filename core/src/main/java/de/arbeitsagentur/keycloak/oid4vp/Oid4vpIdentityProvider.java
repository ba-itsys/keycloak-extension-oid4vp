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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.trust.Oid4vpTrustMaterialResolver;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
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
    private final Oid4vpTrustMaterialResolver trustMaterialResolver = new Oid4vpTrustMaterialResolver();

    public Oid4vpIdentityProvider(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        super(session, config);
        this.redirectFlowService = new Oid4vpRedirectFlowService(session, config.getRequestObjectLifespanSeconds());
        this.qrCodeService = new Oid4vpQrCodeService();

        this.callbackProcessor = new Oid4vpCallbackProcessor(
                config,
                config,
                this,
                new VpTokenProcessor(
                        OBJECT_MAPPER,
                        new VpTokenProcessor.Config(
                                session,
                                this::resolveTrust,
                                config.getStatusListMaxCacheTtl(),
                                config.getIssuerMetadataMaxCacheTtl(),
                                config.isEnforceHaip(),
                                config.getClockSkewSeconds(),
                                config.getKbJwtMaxAgeSeconds())));

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
    public Response retrieveToken(
            KeycloakSession session, FederatedIdentityModel identity, UserSessionModel userSession, UserModel user) {
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
        RealmModel realm = session.getContext().getRealm();
        Map<String, CredentialTypeSpec> credentialTypes = realm == null
                ? Map.of()
                : DcqlQueryBuilder.aggregateFromMappers(
                        realm.getIdentityProviderMappersByAliasStream(
                                getConfig().getAlias()),
                        getConfig());

        if (credentialTypes.isEmpty()) {
            throw new IdentityBrokerException(
                    "No DCQL query configured. Add at least one OID4VP mapper with a credential type to the identity provider.");
        }

        Oid4vpTrustedAuthoritiesMode trustedAuthoritiesMode = getConfig().getTrustedAuthoritiesMode();
        ResolvedTrust trustedAuthoritiesTrust =
                trustedAuthoritiesMode.isEnabled() ? resolveTrust() : ResolvedTrust.empty();
        warnIfTrustedAuthoritiesMissing(trustedAuthoritiesMode, trustedAuthoritiesTrust);
        String dcqlQuery = DcqlQueryBuilder.fromMapperSpecs(
                        OBJECT_MAPPER,
                        credentialTypes,
                        getConfig().isAllCredentialsRequired(),
                        getConfig().getCredentialSetPurpose(),
                        trustedAuthoritiesMode,
                        trustedAuthoritiesTrust.trustListUrls(),
                        trustedAuthoritiesTrust.authorityKeyIdentifiers())
                .build();
        List<RequestedCredential> requestedCredentials =
                credentialTypes.values().stream().map(RequestedCredential::of).toList();
        return new PreparedDcqlQuery(dcqlQuery, requestedCredentials);
    }

    /** Resolves the aggregated trust material of the configured trust material identity providers. */
    public ResolvedTrust resolveTrust() {
        return trustMaterialResolver.resolveTrust(session, getConfig().getTrustMaterialIdps());
    }

    /**
     * Warns when an enabled trusted authorities mode resolves to no value, because the query then
     * silently carries no {@code trusted_authorities} constraint at all and any issuer is accepted.
     */
    private void warnIfTrustedAuthoritiesMissing(Oid4vpTrustedAuthoritiesMode mode, ResolvedTrust trust) {
        String missingMaterial =
                switch (mode) {
                    case NONE -> null;
                    case AKI -> trust.authorityKeyIdentifiers().isEmpty() ? "certificate key identifiers" : null;
                    case ETSI_TL -> trust.trustListUrls().isEmpty() ? "trust list URLs" : null;
                };
        if (missingMaterial != null) {
            LOG.warnf(
                    "OID4VP IdP '%s': trusted_authorities type '%s' is enabled, but the trust material identity providers '%s' expose no %s",
                    getConfig().getAlias(), mode.configValue(), getConfig().getTrustMaterialIdps(), missingMaterial);
        }
    }

    private LoginContext initializeLoginContext(AuthenticationRequest request, AuthenticationSessionModel authSession) {
        String clientId = computeBaseClientId(request);
        String effectiveClientId = computeEffectiveClientId(clientId);

        var uriInfo = request.getUriInfo();
        String requestTabId = uriInfo.getQueryParameters().getFirst(Oid4vpConstants.PARAM_TAB_ID);
        String rootSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
        String authSessionTabId = authSession.getTabId();
        String flowTabId = StringUtil.isNotBlank(authSessionTabId) ? authSessionTabId : requestTabId;
        if (StringUtil.isNotBlank(requestTabId)
                && StringUtil.isNotBlank(authSessionTabId)
                && !requestTabId.equals(authSessionTabId)) {
            LOG.debugf(
                    "OID4VP login tab_id mismatch, using auth session tab for flow binding: requestTabId=%s authSessionTabId=%s",
                    requestTabId, authSessionTabId);
        }

        return new LoginContext(rootSessionId, flowTabId, effectiveClientId);
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
        String state = StringUtil.isBlank(loginContext.flowTabId())
                ? UUID.randomUUID().toString()
                : loginContext.flowTabId() + "." + UUID.randomUUID();
        String responseUri = computeVerifierResponseUri();

        String nonce = UUID.randomUUID().toString();
        String encryptionKeyJson = null;
        String encryptionJwkThumbprint = null;
        if (getConfig().getResolvedResponseMode().requiresEncryption()) {
            Oid4vpJwk responseEncryptionKey = redirectFlowService.createResponseEncryptionKey(state);
            encryptionKeyJson = responseEncryptionKey.toJson();
            encryptionJwkThumbprint = Oid4vpRequestObjectStore.computeEncryptionJwkThumbprint(encryptionKeyJson);
        }
        PreparedDcqlQuery preparedDcqlQuery = prepareDcqlQueryFromConfig();

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                loginContext.rootSessionId(),
                loginContext.flowTabId(),
                loginContext.effectiveClientId(),
                responseUri,
                flow,
                nonce,
                encryptionKeyJson,
                encryptionJwkThumbprint,
                preparedDcqlQuery.configuredCredentialTypes(),
                preparedDcqlQuery.requestedCredentials());
        requestObjectStore.storeRequestContext(session, requestContext);

        URI requestUri = request.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(request.getRealm().getName())
                .path("broker")
                .path(getConfig().getAlias())
                .path("endpoint")
                .path("request-object")
                .path(state)
                .build();
        String walletUrl = redirectFlowService
                .buildWalletAuthorizationUrl(walletScheme, loginContext.effectiveClientId(), requestUri)
                .toString();
        return new FlowEntry(state, walletUrl);
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

        FlowEntry crossDeviceFlow = redirectFlowData.crossDeviceFlow();
        String crossDeviceState = crossDeviceFlow != null ? crossDeviceFlow.state() : null;
        String sameDeviceWalletUrl = redirectFlowData.sameDeviceFlow() != null
                ? redirectFlowData.sameDeviceFlow().walletUrl()
                : null;
        String crossDeviceWalletUrl = crossDeviceFlow != null ? crossDeviceFlow.walletUrl() : null;

        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("crossDeviceState", crossDeviceState)
                .setAttribute("currentBrokerAlias", getConfig().getAlias())
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

    record LoginContext(String rootSessionId, String flowTabId, String effectiveClientId) {}

    record FlowEntry(String state, String walletUrl) {}

    record RedirectFlowData(FlowEntry sameDeviceFlow, FlowEntry crossDeviceFlow, String qrCodeBase64) {
        static final RedirectFlowData EMPTY = new RedirectFlowData(null, null, null);
    }
}
