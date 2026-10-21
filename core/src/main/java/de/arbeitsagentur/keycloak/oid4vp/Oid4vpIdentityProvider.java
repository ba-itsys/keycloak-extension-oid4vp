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
import de.arbeitsagentur.keycloak.oid4vp.authentication.Oid4vpAuthenticationCallback;
import de.arbeitsagentur.keycloak.oid4vp.authentication.Oid4vpPresentationSession;
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpCredentialSetsValidator;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpPresentationFlow;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService;
import de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService;
import de.arbeitsagentur.keycloak.oid4vp.trust.CredentialTrustPlan;
import de.arbeitsagentur.keycloak.oid4vp.trust.Oid4vpTrustMaterialResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpQrCodeService;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.broker.oid4vp.EphemeralKey;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.util.Time;
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
import org.keycloak.models.utils.SessionExpiration;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Keycloak identity provider that acts as an OID4VP verifier and accepts verifiable credentials
 * from a wallet as a login, over the same-device flow (wallet redirect) and the cross-device flow
 * (QR code).
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
                                config.getKbJwtMaxAgeSeconds(),
                                config.isRequireIssuerSanMatch())),
                ReferenceCredentialBinding.checkOf(session));

        RealmModel realm = session.getContext().getRealm();
        int authSessionLifespanSeconds =
                realm != null ? SessionExpiration.getAuthSessionLifespan(realm) : DEFAULT_LOGIN_TIMEOUT_SECONDS;
        this.requestObjectStore =
                new Oid4vpRequestObjectStore(Duration.ofSeconds(authSessionLifespanSeconds), config.getAlias());
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
            return renderLoginPage(authSession, initializeLoginContext(request, authSession));
        } catch (Exception e) {
            LOG.errorf(e, "Failed to initiate OID4VP login: %s", e.getMessage());
            throw new IdentityBrokerException("Failed to initiate wallet login", e);
        }
    }

    protected Response refreshLoginPage(AuthenticationSessionModel authSession) {
        LoginContext loginContext = new LoginContext(
                authSession.getParentSession().getId(),
                authSession.getTabId(),
                computeEffectiveClientId(computeBaseClientId()));
        return renderLoginPage(authSession, loginContext);
    }

    protected Response renderExpiredPage(AuthenticationSessionModel authSession) {
        boolean crossDeviceInProgress = !crossDeviceStates(authSession).isEmpty();
        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("refreshUrl", endpointUrl("refresh", authSession))
                .setAttribute(
                        "crossDeviceStatusUrl",
                        crossDeviceInProgress ? endpointUrl("cross-device/status", authSession) : null)
                .createForm("login-oid4vp-expired.ftl");
    }

    protected Response renderLoginPage(AuthenticationSessionModel authSession, LoginContext loginContext) {
        boolean sameDeviceConfigured = getConfig().isSameDeviceEnabled();
        boolean crossDeviceConfigured = getConfig().isCrossDeviceEnabled();
        int requestedLoa = requestedLevelOfAuthentication(authSession);
        boolean sameDeviceEnabled =
                sameDeviceConfigured && flowOfferedAt(getConfig().getSameDeviceLoa(), requestedLoa);
        boolean crossDeviceEnabled =
                crossDeviceConfigured && flowOfferedAt(getConfig().getCrossDeviceLoa(), requestedLoa);

        // A flow below the requested level gets no state and no request object, so nothing a wallet
        // posts can complete it.
        if (!sameDeviceEnabled && !crossDeviceEnabled && (sameDeviceConfigured || crossDeviceConfigured)) {
            LOG.debugf(
                    "OID4VP IdP '%s': no flow is offered at the requested level of authentication %d",
                    getConfig().getAlias(), requestedLoa);
            new EventBuilder(
                            session.getContext().getRealm(),
                            session,
                            session.getContext().getConnection())
                    .event(EventType.LOGIN_ERROR)
                    .detail(
                            Details.REASON,
                            "No OID4VP flow is offered at the requested level of authentication " + requestedLoa)
                    .error(Errors.NOT_ALLOWED);
            return ErrorPage.error(
                    session, authSession, Response.Status.FORBIDDEN, Oid4vpMessages.NOT_AVAILABLE_FOR_REQUESTED_LEVEL);
        }

        RedirectFlowData redirectFlowData = buildRedirectFlowData(loginContext, sameDeviceEnabled, crossDeviceEnabled);

        return buildLoginFormResponse(authSession, redirectFlowData, sameDeviceEnabled, crossDeviceEnabled);
    }

    /**
     * Stores the presentation flow as a user session note so that tokens can carry it without a
     * mapper. Keycloak's first broker login clears the user session notes, so every hook sets the
     * note again: preprocessing runs before the first broker login and the user centric hooks run
     * after it.
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

    /**
     * Keycloak calls this for every brokered login once it resolved the user (an existing link, a new
     * user, or an account the first broker login flow linked), so it also records the level reached.
     */
    @Override
    public void updateBrokeredUser(
            KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        setPresentationFlowSessionNote(context);
        recordLevelOfAuthentication(session, context);
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
        AuthenticationCallback routed = new Oid4vpAuthenticationCallback(session, this, getConfig(), callback);
        return new Oid4vpIdentityProviderEndpoint(session, realm, this, routed, event, requestObjectStore);
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
     * Collects the {@code trusted_authorities} entries for every credential from the trust material
     * identity providers that serve its credential types. Only those providers know whether their
     * trust domain may be advertised, so no verifier wide setting overrides them. An entry that
     * accepts several types advertises the trust domains of all of them.
     */
    private static Map<String, List<TrustedAuthority>> trustedAuthorities(
            Map<String, CredentialTypeSpec> credentialTypes, CredentialTrustPlan trustPlan) {
        Map<String, List<TrustedAuthority>> trustedAuthorities = new LinkedHashMap<>();
        credentialTypes.forEach((credentialId, spec) -> trustedAuthorities.put(
                credentialId,
                TrustedAuthority.merge(spec.types().stream()
                        .flatMap(type -> trustPlan.trustedAuthoritiesFor(type).stream())
                        .toList())));
        return trustedAuthorities;
    }

    /**
     * Validates the credential set configuration again, because identity provider mappers have no
     * validation hook and a mapper edited after the provider was last saved can invalidate a
     * configuration the admin console accepted. A wallet would reject an inconsistent query with an
     * opaque error.
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

    public CredentialTrustPlan resolveTrustPlan() {
        return trustMaterialResolver.resolvePlan(session, getConfig().getTrustMaterialIdps());
    }

    /**
     * Warns about requested credential types that no trust material identity provider serves, but
     * only when the providers declare credential types at all, because an unscoped provider serves
     * everything and cannot leave a type uncovered.
     */
    private void warnIfCredentialTypesAreUnserved(
            Map<String, CredentialTypeSpec> credentialTypes, CredentialTrustPlan trustPlan) {
        if (!trustPlan.isScopedByCredentialType()) {
            return;
        }
        credentialTypes.forEach((credentialId, spec) -> spec.types().stream()
                .filter(type -> !trustPlan.serves(type))
                .forEach(type -> LOG.warnf(
                        "OID4VP IdP '%s': no trust material identity provider of '%s' serves the credential type '%s' "
                                + "requested as '%s'; presentations of that credential cannot be verified",
                        getConfig().getAlias(), getConfig().getTrustMaterialIdps(), type, credentialId)));
    }

    /**
     * Returns the level of authentication the client requested, or {@link Constants#NO_LOA} when
     * the request names none. Keycloak derives the value from the acr_values or claims parameter
     * through the realm or client ACR-to-LoA mapping, and both OIDC and SAML set the client note.
     */
    private static int requestedLevelOfAuthentication(AuthenticationSessionModel authSession) {
        String requestedLoa = authSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION);
        return StringUtil.isBlank(requestedLoa) ? Constants.NO_LOA : Integer.parseInt(requestedLoa);
    }

    static boolean flowOfferedAt(Integer flowLoa, int requestedLoa) {
        return flowLoa == null || requestedLoa <= flowLoa;
    }

    /**
     * Returns the level of the flow the presentation arrived over. A presentation without the
     * subject credential identified nobody. Another step of the first broker login flow found the
     * user, so such a login reaches no level here.
     */
    static Integer levelReached(Oid4vpIdentityProviderConfig config, BrokeredIdentityContext context) {
        if (context.getContextData().containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY)) {
            return null;
        }
        Oid4vpPresentationFlow flow = Oid4vpMapperUtils.presentationFlow(context);
        if (flow == null) {
            return null;
        }
        return switch (flow) {
            case SAME_DEVICE -> config.getSameDeviceLoa();
            case CROSS_DEVICE -> config.getCrossDeviceLoa();
        };
    }

    /**
     * Records the level a login reached the way the browser flow's level condition does: for the
     * token of this login and, with the time, in the user session for single sign-on, within the max
     * age the browser flow configures for that level. Runs only once the broker resolved the user,
     * never for a presentation step of another flow, so a presentation that a later check refuses
     * records nothing.
     */
    private void recordLevelOfAuthentication(KeycloakSession session, BrokeredIdentityContext context) {
        Integer level = levelReached(getConfig(), context);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (level == null || authSession == null) {
            return;
        }
        new AcrStore(session, authSession).setLevelAuthenticated(level);
        context.setSessionNote(Constants.LOA_MAP, authSession.getAuthNote(Constants.LOA_MAP));
        LOG.debugf(
                "OID4VP IdP '%s': the login reached level of authentication %d",
                getConfig().getAlias(), level);
    }

    protected LoginContext initializeLoginContext(
            AuthenticationRequest request, AuthenticationSessionModel authSession) {
        String effectiveClientId = computeEffectiveClientId(computeBaseClientId());

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

    protected RedirectFlowData buildRedirectFlowData(
            LoginContext loginContext, boolean sameDeviceEnabled, boolean crossDeviceEnabled) {
        if (!sameDeviceEnabled && !crossDeviceEnabled) {
            return RedirectFlowData.EMPTY;
        }

        FlowEntry sameDeviceFlow = null;
        FlowEntry crossDeviceFlow = null;
        String qrCodeBase64 = null;

        // Lets a failure such as an invalid credential set configuration propagate to performLogin,
        // which renders Keycloak's error page. A caught failure would leave a wallet login page with
        // no button and no QR code.
        if (sameDeviceEnabled) {
            sameDeviceFlow = createFlowEntry(
                    loginContext,
                    Oid4vpConstants.FLOW_SAME_DEVICE,
                    getConfig().getSameDeviceRequestUriLifetimeSeconds());
        }

        if (crossDeviceEnabled) {
            crossDeviceFlow = createFlowEntry(
                    loginContext,
                    Oid4vpConstants.FLOW_CROSS_DEVICE,
                    getConfig().getCrossDeviceRequestUriLifetimeSeconds());
            qrCodeBase64 = qrCodeService.generateQrCode(crossDeviceFlow.walletUrl(), QR_CODE_SIZE, QR_CODE_SIZE);
        }

        return new RedirectFlowData(sameDeviceFlow, crossDeviceFlow, qrCodeBase64);
    }

    protected FlowEntry createFlowEntry(LoginContext loginContext, String flow, int requestUriLifetimeSeconds) {
        String state = StringUtil.isBlank(loginContext.flowTabId())
                ? UUID.randomUUID().toString()
                : loginContext.flowTabId() + "." + UUID.randomUUID();
        String responseUri = computeVerifierResponseUri();

        String nonce = UUID.randomUUID().toString();
        // The flow state is the key id, so an encrypted direct_post.jwt callback resolves its request
        // context from the cleartext JWE header alone.
        EphemeralKey encryptionKey =
                getConfig().getResolvedResponseMode().requiresEncryption() ? EphemeralKey.generate(state) : null;
        PreparedDcqlQuery preparedDcqlQuery = prepareDcqlQueryFromConfig();
        long requestUriExpiresAtEpochSeconds = (long) Time.currentTime() + requestUriLifetimeSeconds;

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                loginContext.rootSessionId(),
                loginContext.flowTabId(),
                loginContext.effectiveClientId(),
                responseUri,
                flow,
                nonce,
                encryptionKey,
                preparedDcqlQuery.requestedCredentials(),
                preparedDcqlQuery.credentialSets(),
                preparedDcqlQuery.dcqlQuery(),
                requestUriExpiresAtEpochSeconds);
        requestObjectStore.storeRequestContext(session, requestContext);

        URI requestUri = UriBuilder.fromUri(responseUri)
                .path("request-object")
                .path(state)
                .build();
        String walletUrl = redirectFlowService
                .buildWalletAuthorizationUrl(
                        getConfig().getWalletScheme(),
                        loginContext.effectiveClientId(),
                        requestUri,
                        getConfig().isRequestUriMethodPost())
                .toString();
        return new FlowEntry(state, walletUrl, requestUriExpiresAtEpochSeconds);
    }

    protected String computeEffectiveClientId(String clientId) {
        Oid4vpClientIdScheme clientIdScheme = getConfig().getResolvedClientIdScheme();
        return clientIdScheme.computeClientId(clientId, getConfig().getX509CertificatePem());
    }

    protected Response buildLoginFormResponse(
            AuthenticationSessionModel authSession,
            RedirectFlowData redirectFlowData,
            boolean sameDeviceEnabled,
            boolean crossDeviceEnabled) {

        FlowEntry sameDeviceFlow = redirectFlowData.sameDeviceFlow();
        FlowEntry crossDeviceFlow = redirectFlowData.crossDeviceFlow();
        requestObjectStore
                .rememberStates(
                        session,
                        authSession,
                        Stream.of(sameDeviceFlow, crossDeviceFlow)
                                .filter(Objects::nonNull)
                                .map(FlowEntry::state)
                                .toList(),
                        getConfig().getMaxLiveRequestsPerLogin())
                .forEach(state -> Oid4vpDirectPostService.endAttempt(session, requestObjectStore, authSession, state));

        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setAttribute("currentBrokerAlias", getConfig().getAlias())
                .setAttribute(
                        "alternativeProvidersOffered",
                        !Oid4vpPresentationSession.isPending(
                                authSession, getConfig().getAlias()))
                .setAttribute("sameDeviceEnabled", sameDeviceEnabled)
                .setAttribute("crossDeviceEnabled", crossDeviceEnabled)
                .setAttribute("sameDeviceWalletUrl", sameDeviceFlow != null ? sameDeviceFlow.walletUrl() : null)
                .setAttribute("crossDeviceWalletUrl", crossDeviceFlow != null ? crossDeviceFlow.walletUrl() : null)
                .setAttribute(
                        "requestUriExpiresInSeconds",
                        requestUriExpiresInSeconds(authSession, sameDeviceFlow, crossDeviceFlow))
                .setAttribute("requestUriExpiredUrl", endpointUrl("expired", authSession))
                .setAttribute("qrCodeBase64", redirectFlowData.qrCodeBase64())
                .setAttribute(
                        "crossDeviceStatusUrl",
                        crossDeviceEnabled ? endpointUrl("cross-device/status", authSession) : null)
                .setAttribute("crossDevicePollIntervalMs", getConfig().getSsePollIntervalMs())
                .createForm("login-oid4vp-idp.ftl");
    }

    /**
     * Counts down to the first request URI on the page to expire, or to the end of the
     * authentication session when that comes first.
     */
    protected long requestUriExpiresInSeconds(AuthenticationSessionModel authSession, FlowEntry... flows) {
        long authSessionExpiresAt = SessionExpiration.getAuthSessionExpiration(
                session.getContext().getRealm(), authSession.getParentSession().getTimestamp());
        long expiresAt = Stream.of(flows)
                .filter(Objects::nonNull)
                .mapToLong(FlowEntry::requestUriExpiresAtEpochSeconds)
                .reduce(authSessionExpiresAt, Math::min);
        return Math.max(0, expiresAt - Time.currentTime());
    }

    List<String> crossDeviceStates(AuthenticationSessionModel authSession) {
        return requestObjectStore.liveRequestContexts(session, authSession).stream()
                .filter(context -> Oid4vpConstants.FLOW_CROSS_DEVICE.equals(context.flow()))
                .map(Oid4vpRequestObjectStore.RequestContextEntry::state)
                .toList();
    }

    private String endpointUrl(String path, AuthenticationSessionModel authSession) {
        return UriBuilder.fromUri(computeVerifierResponseUri())
                .path(path)
                .queryParam(Oid4vpConstants.PARAM_TAB_ID, authSession.getTabId())
                .queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId())
                .build()
                .toString();
    }

    protected String computeVerifierResponseUri() {
        return Oid4vpConstants.buildEndpointBaseUrl(
                session.getContext().getUri().getBaseUri(),
                session.getContext().getRealm().getName(),
                getConfig().getAlias());
    }

    protected String computeBaseClientId() {
        URI realmBase = session.getContext()
                .getUri()
                .getBaseUriBuilder()
                .path("realms")
                .path(session.getContext().getRealm().getName())
                .build();
        String value = realmBase.toString();
        return value.endsWith("/") ? value : value + "/";
    }

    protected record LoginContext(String rootSessionId, String flowTabId, String effectiveClientId) {}

    protected record FlowEntry(String state, String walletUrl, long requestUriExpiresAtEpochSeconds) {}

    protected record RedirectFlowData(FlowEntry sameDeviceFlow, FlowEntry crossDeviceFlow, String qrCodeBase64) {
        static final RedirectFlowData EMPTY = new RedirectFlowData(null, null, null);
    }
}
