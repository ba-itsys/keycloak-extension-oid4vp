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
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpCredentialSetsValidator;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpPresentationFlow;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.trust.CredentialTrustPlan;
import de.arbeitsagentur.keycloak.oid4vp.trust.Oid4vpTrustMaterialResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
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
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 1800;
    private static final int QR_CODE_SIZE = 250;
    private static final String INVALID_CREDENTIAL_SETS = "Invalid OID4VP credential set configuration: ";
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
                                this::resolveTrustPlan,
                                config.getStatusListMaxCacheTtl(),
                                config.getIssuerMetadataMaxCacheTtl(),
                                config.getClockSkewSeconds(),
                                config.getKbJwtMaxAgeSeconds())),
                ReferenceCredentialBinding.checkOf(session));

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

            boolean sameDeviceConfigured = getConfig().isSameDeviceEnabled();
            boolean crossDeviceConfigured = getConfig().isCrossDeviceEnabled();
            int requestedLoa = requestedLevelOfAuthentication(authSession);
            boolean sameDeviceEnabled =
                    sameDeviceConfigured && flowOfferedAt(getConfig().getSameDeviceMaxLoa(), requestedLoa);
            boolean crossDeviceEnabled =
                    crossDeviceConfigured && flowOfferedAt(getConfig().getCrossDeviceMaxLoa(), requestedLoa);

            // The state of a flow above its ceiling is never created, so no request object exists
            // for it and nothing a wallet posts can complete it.
            if (!sameDeviceEnabled && !crossDeviceEnabled && (sameDeviceConfigured || crossDeviceConfigured)) {
                LOG.debugf(
                        "OID4VP IdP '%s': no flow is offered at the requested level of authentication %d",
                        getConfig().getAlias(), requestedLoa);
                new EventBuilder(
                                request.getRealm(),
                                session,
                                session.getContext().getConnection())
                        .event(EventType.LOGIN_ERROR)
                        .detail(
                                Details.REASON,
                                "No OID4VP flow is offered at the requested level of authentication " + requestedLoa)
                        .error(Errors.NOT_ALLOWED);
                return ErrorPage.error(
                        session,
                        authSession,
                        Response.Status.FORBIDDEN,
                        Oid4vpMessages.NOT_AVAILABLE_FOR_REQUESTED_LEVEL);
            }

            RedirectFlowData redirectFlowData =
                    buildRedirectFlowData(request, authSession, loginContext, sameDeviceEnabled, crossDeviceEnabled);

            return buildLoginFormResponse(authSession, redirectFlowData, sameDeviceEnabled, crossDeviceEnabled);

        } catch (Exception e) {
            LOG.errorf(e, "Failed to initiate OID4VP login: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to initiate wallet login", e);
        }
    }

    /**
     * The presentation flow travels as a user session note so tokens can surface it without a
     * mapper. Keycloak's first broker login clears the user session notes, so the note is set on
     * every hook: preprocessing runs before the first broker login, the user centric hooks after
     * it.
     */
    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session, RealmModel realm, BrokeredIdentityContext context) {
        setPresentationFlowSessionNote(context);
    }

    @Override
    public void importNewUser(
            KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        setPresentationFlowSessionNote(context);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        setPresentationFlowSessionNote(context);
    }

    private static void setPresentationFlowSessionNote(BrokeredIdentityContext context) {
        Oid4vpPresentationFlow flow = Oid4vpMapperUtils.presentationFlow(context);
        if (flow != null) {
            context.setSessionNote(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY, flow.value());
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

    public PreparedDcqlQuery prepareDcqlQueryFromConfig() {
        RealmModel realm = session.getContext().getRealm();
        DcqlQueryBuilder.AggregatedCredentials aggregated = realm == null
                ? new DcqlQueryBuilder.AggregatedCredentials(Map.of(), List.of())
                : DcqlQueryBuilder.aggregateFromMappers(
                        realm.getIdentityProviderMappersByAliasStream(
                                getConfig().getAlias()),
                        getConfig());
        if (!aggregated.problems().isEmpty()) {
            throw new IdentityBrokerException(INVALID_CREDENTIAL_SETS + String.join("; ", aggregated.problems()));
        }
        Map<String, CredentialTypeSpec> credentialTypes = aggregated.credentials();

        if (credentialTypes.isEmpty()) {
            throw new IdentityBrokerException(
                    "No DCQL query configured. Add at least one OID4VP mapper with a credential type to the identity provider.");
        }

        List<CredentialSet> credentialSets = validatedCredentialSets(credentialTypes);

        CredentialTrustPlan trustPlan = resolveTrustPlan();
        warnIfCredentialTypesAreUnserved(credentialTypes, trustPlan);
        String dcqlQuery = DcqlQueryBuilder.fromMapperSpecs(
                        OBJECT_MAPPER, credentialTypes, credentialSets, trustedAuthorities(credentialTypes, trustPlan))
                .build();
        List<RequestedCredential> requestedCredentials = credentialTypes.entrySet().stream()
                .map(entry -> RequestedCredential.of(entry.getKey(), entry.getValue()))
                .toList();
        return new PreparedDcqlQuery(dcqlQuery, requestedCredentials, credentialSets);
    }

    /**
     * The {@code trusted_authorities} entries of every credential, taken from the trust material
     * identity providers serving its credential type. Only they know whether their trust domain can
     * be advertised at all, so there is no verifier-wide setting to override them.
     */
    private static Map<String, List<TrustedAuthority>> trustedAuthorities(
            Map<String, CredentialTypeSpec> credentialTypes, CredentialTrustPlan trustPlan) {
        Map<String, List<TrustedAuthority>> trustedAuthorities = new LinkedHashMap<>();
        credentialTypes.forEach((credentialId, spec) ->
                trustedAuthorities.put(credentialId, trustPlan.trustedAuthoritiesFor(spec.type())));
        return trustedAuthorities;
    }

    /**
     * The credential set configuration is validated again here because identity provider mappers
     * have no validation hook: a mapper edited after the provider was last saved can invalidate a
     * configuration the admin console accepted. Failing here is deliberate, since an inconsistent
     * query would only be rejected by the wallet with an opaque error.
     */
    private List<CredentialSet> validatedCredentialSets(Map<String, CredentialTypeSpec> credentialTypes) {
        List<CredentialSet> credentialSets;
        try {
            credentialSets = getConfig().getParsedCredentialSets();
        } catch (IllegalArgumentException e) {
            throw new IdentityBrokerException(INVALID_CREDENTIAL_SETS + e.getMessage(), e);
        }

        List<String> problems = Oid4vpCredentialSetsValidator.problems(
                credentialSets,
                credentialTypes,
                getConfig().getPrincipalAttributes(),
                !getConfig().isTransientUsersEnabled(),
                getConfig().isAllowMissingSubjectCredential());
        if (!problems.isEmpty()) {
            throw new IdentityBrokerException(INVALID_CREDENTIAL_SETS + String.join("; ", problems));
        }
        return credentialSets;
    }

    /** Resolves the configured trust material identity providers into a per credential type plan. */
    public CredentialTrustPlan resolveTrustPlan() {
        return trustMaterialResolver.resolvePlan(session, getConfig().getTrustMaterialIdps());
    }

    /**
     * Warns about requested credential types that no trust material identity provider serves. Only
     * reported once the providers declare credential types at all, because an unscoped provider
     * serves everything and cannot leave a type uncovered.
     */
    private void warnIfCredentialTypesAreUnserved(
            Map<String, CredentialTypeSpec> credentialTypes, CredentialTrustPlan trustPlan) {
        if (!trustPlan.isScopedByCredentialType()) {
            return;
        }
        credentialTypes.forEach((credentialId, spec) -> {
            if (!trustPlan.serves(spec.type())) {
                LOG.warnf(
                        "OID4VP IdP '%s': no trust material identity provider of '%s' serves the credential type '%s' "
                                + "requested as '%s'; presentations of that credential cannot be verified",
                        getConfig().getAlias(), getConfig().getTrustMaterialIdps(), spec.type(), credentialId);
            }
        });
    }

    /**
     * The level of authentication the client requested, as Keycloak derives it from the acr_values
     * or claims parameter through the realm or client ACR-to-LoA mapping. OIDC and SAML both set
     * the client note. {@link Constants#NO_LOA} when the request names none.
     */
    private static int requestedLevelOfAuthentication(AuthenticationSessionModel authSession) {
        String requestedLoa = authSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION);
        return StringUtil.isBlank(requestedLoa) ? Constants.NO_LOA : Integer.parseInt(requestedLoa);
    }

    static boolean flowOfferedAt(Integer maxLoa, int requestedLoa) {
        return maxLoa == null || requestedLoa <= maxLoa;
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

        // A failure here (for example an invalid credential-set configuration, see validatedCredentialSets)
        // is deliberately not swallowed: it propagates to performLogin, which renders Keycloak's error
        // page instead of a wallet login page with no button and no QR code.
        if (sameDeviceEnabled) {
            sameDeviceFlow = createFlowEntry(
                    request,
                    loginContext,
                    Oid4vpConstants.FLOW_SAME_DEVICE,
                    getConfig().getWalletScheme());
        }

        if (crossDeviceEnabled) {
            crossDeviceFlow = createFlowEntry(
                    request,
                    loginContext,
                    Oid4vpConstants.FLOW_CROSS_DEVICE,
                    getConfig().getWalletScheme());
            qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceFlow.walletUrl(), QR_CODE_SIZE, QR_CODE_SIZE);
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
                preparedDcqlQuery.requestedCredentials(),
                preparedDcqlQuery.credentialSets(),
                preparedDcqlQuery.dcqlQuery());
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
                .buildWalletAuthorizationUrl(
                        walletScheme,
                        loginContext.effectiveClientId(),
                        requestUri,
                        getConfig().isRequestUriMethodPost())
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
