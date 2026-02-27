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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class Oid4vpIdentityProvider extends AbstractIdentityProvider<Oid4vpIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProvider.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static final String SESSION_STATE = "oid4vp_state";
    static final String SESSION_NONCE = "oid4vp_nonce";
    static final String SESSION_RESPONSE_URI = "oid4vp_response_uri";
    static final String SESSION_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    static final String SESSION_ENCRYPTION_KEY = "oid4vp_encryption_key";
    static final String SESSION_CLIENT_ID = "oid4vp_client_id";
    static final String SESSION_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";
    static final String SESSION_MDOC_GENERATED_NONCE = "oid4vp_mdoc_generated_nonce";

    protected final ObjectMapper objectMapper;
    private final Oid4vpRedirectFlowService redirectFlowService;
    private final Oid4vpQrCodeService qrCodeService;
    private final VpTokenProcessor vpTokenProcessor;
    private final Oid4vpResponseDecryptor responseDecryptor;
    private final Oid4vpRequestObjectStore requestObjectStore;
    private final int loginTimeoutSeconds;

    public Oid4vpIdentityProvider(KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        super(session, config);
        this.objectMapper = new ObjectMapper();
        this.redirectFlowService = new Oid4vpRedirectFlowService(session, objectMapper);
        this.qrCodeService = new Oid4vpQrCodeService();
        this.vpTokenProcessor = new VpTokenProcessor(objectMapper);
        this.responseDecryptor = new Oid4vpResponseDecryptor();

        RealmModel realm = session.getContext().getRealm();
        this.loginTimeoutSeconds = realm != null ? realm.getAccessCodeLifespanLogin() : 1800;
        this.requestObjectStore = new Oid4vpRequestObjectStore(Duration.ofSeconds(loginTimeoutSeconds));
    }

    Oid4vpRedirectFlowService getRedirectFlowService() {
        return redirectFlowService;
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

    public BrokeredIdentityContext processCallback(
            AuthenticationSessionModel authSession,
            String state,
            String vpToken,
            String encryptedResponse,
            String error,
            String errorDescription) {

        String expectedState = authSession.getAuthNote(SESSION_STATE);
        if (expectedState == null || !expectedState.equals(state)) {
            throw new IdentityBrokerException("Invalid state parameter");
        }

        if (StringUtil.isNotBlank(error)) {
            String message = StringUtil.isNotBlank(errorDescription) ? error + ": " + errorDescription : error;
            throw new IdentityBrokerException("Wallet returned error: " + message);
        }

        String mdocGeneratedNonce = authSession.getAuthNote(SESSION_MDOC_GENERATED_NONCE);
        if (mdocGeneratedNonce != null) {
            authSession.removeAuthNote(SESSION_MDOC_GENERATED_NONCE);
        }

        if (StringUtil.isBlank(vpToken) && StringUtil.isNotBlank(encryptedResponse)) {
            String encryptionKey = authSession.getAuthNote(SESSION_ENCRYPTION_KEY);
            try {
                vpToken = responseDecryptor.decryptVpToken(encryptedResponse, encryptionKey);
            } catch (Exception e) {
                throw new IdentityBrokerException("Failed to decrypt response: " + e.getMessage(), e);
            }
        }

        if (StringUtil.isBlank(vpToken)) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        String expectedNonce = authSession.getAuthNote(SESSION_NONCE);
        String responseUri = authSession.getAuthNote(SESSION_RESPONSE_URI);
        String effectiveClientId = authSession.getAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        String clientId = effectiveClientId != null ? effectiveClientId : authSession.getAuthNote(SESSION_CLIENT_ID);
        String redirectFlowResponseUri = authSession.getAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        boolean trustX5c = getConfig().getEffectiveTrustX5cFromCredential();
        boolean skipSignatureVerification = getConfig().isSkipTrustListVerification();

        VpTokenProcessor.Result vpResult = vpTokenProcessor.process(
                vpToken,
                clientId,
                expectedNonce,
                responseUri,
                trustX5c,
                skipSignatureVerification,
                redirectFlowResponseUri,
                mdocGeneratedNonce);

        VpTokenProcessor.VerifiedCredential primary = vpResult.getPrimaryCredential();
        if (primary == null) {
            throw new IdentityBrokerException("No valid credential found in VP token");
        }

        String issuer = primary.issuer() != null ? primary.issuer() : "unknown";
        String credentialType = primary.credentialType();

        if (!getConfig().isIssuerAllowed(issuer)) {
            throw new IdentityBrokerException("Issuer not allowed: " + issuer);
        }
        if (!getConfig().isCredentialTypeAllowed(credentialType)) {
            throw new IdentityBrokerException("Credential type not allowed: " + credentialType);
        }

        Map<String, Object> claims = vpResult.isMultiCredential() ? vpResult.mergedClaims() : primary.claims();
        String credentialFormat = primary.presentationType() == VpTokenProcessor.PresentationType.MDOC
                ? Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC
                : Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
        String userMappingClaimName = getConfig().getUserMappingClaimForFormat(credentialFormat);
        String subject = extractNestedClaim(claims, userMappingClaimName);

        if (StringUtil.isBlank(subject)) {
            throw new IdentityBrokerException("Missing subject claim '" + userMappingClaimName + "' in credential");
        }

        String identityKey = FederatedIdentityKeyGenerator.generate(issuer, credentialType, subject);

        BrokeredIdentityContext context = new BrokeredIdentityContext(identityKey, getConfig());
        context.setIdp(this);
        context.setUsername(subject);
        context.getContextData().put("oid4vp_claims", claims);
        context.getContextData().put("oid4vp_issuer", issuer);
        context.getContextData().put("oid4vp_subject", subject);
        context.getContextData().put("oid4vp_credential_type", credentialType);
        context.getContextData()
                .put("oid4vp_presentation_type", primary.presentationType().name());

        clearSessionNotes(authSession);
        return context;
    }

    protected String buildDcqlQueryFromConfig() {
        String manual = getConfig().getDcqlQuery();
        if (StringUtil.isNotBlank(manual)) {
            return manual;
        }

        Map<String, DcqlQueryBuilder.CredentialTypeSpec> credentialTypes = aggregateMappersByCredentialType();

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
        authSession.setAuthNote("oid4vp_tab_id", sessionTabId != null ? sessionTabId : "");
        authSession.setAuthNote("oid4vp_client_data", clientData != null ? clientData : "");
        authSession.setAuthNote("oid4vp_session_code", sessionCode != null ? sessionCode : "");

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

        Oid4vpRedirectFlowService.SignedRequestObject signedRequest = redirectFlowService.buildSignedRequestObject(
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
                loginTimeoutSeconds);

        authSession.setAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI, responseUri);
        authSession.setAuthNote(SESSION_RESPONSE_URI, responseUri);
        if (signedRequest.encryptionKeyJson() != null) {
            authSession.setAuthNote(SESSION_ENCRYPTION_KEY, signedRequest.encryptionKeyJson());
        }

        String encryptionPublicKeyJson = extractEncryptionPublicKey(signedRequest.encryptionKeyJson());

        Oid4vpRequestObjectStore.RebuildParams rebuildParams = new Oid4vpRequestObjectStore.RebuildParams(
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
            var encKey = com.nimbusds.jose.jwk.ECKey.parse(encryptionKeyJson);
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

        return session.getProvider(org.keycloak.forms.login.LoginFormsProvider.class)
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

    byte[] computeJwkThumbprint(String jwkJson) {
        if (StringUtil.isBlank(jwkJson)) {
            return null;
        }
        try {
            JWK jwk = JWK.parse(jwkJson);
            return jwk.toPublicJWK().computeThumbprint().decode();
        } catch (Exception e) {
            LOG.warnf("Failed to compute JWK thumbprint: %s", e.getMessage());
            return null;
        }
    }

    private String extractNestedClaim(Map<String, Object> claims, String claimPath) {
        if (claims == null || claimPath == null) return null;

        // Try exact key match first (handles mDoc flat keys like "namespace/element")
        Object direct = claims.get(claimPath);
        if (direct != null) return direct.toString();

        // Fall back to nested path navigation
        String[] pathParts = claimPath.split("/");
        Object current = claims;
        for (String part : pathParts) {
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
                if (current == null) return null;
            } else {
                return null;
            }
        }
        return current != null ? current.toString() : null;
    }

    private Map<String, DcqlQueryBuilder.CredentialTypeSpec> aggregateMappersByCredentialType() {
        Map<String, DcqlQueryBuilder.CredentialTypeSpec> result = new LinkedHashMap<>();

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                return result;
            }

            String idpAlias = getConfig().getAlias();
            Map<String, List<DcqlQueryBuilder.ClaimSpec>> claimsByType = new LinkedHashMap<>();
            Map<String, String> formatByType = new LinkedHashMap<>();

            realm.getIdentityProviderMappersByAliasStream(idpAlias).forEach(mapper -> {
                String format = mapper.getConfig().get("credential.format");
                String type = mapper.getConfig().get("credential.type");
                String claimPath = mapper.getConfig().get("claim");
                boolean isOptional = "true".equalsIgnoreCase(mapper.getConfig().get("optional"));

                if (StringUtil.isBlank(format)) {
                    format = Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
                }
                if (StringUtil.isBlank(type)) {
                    return;
                }

                String typeKey = format + DcqlQueryBuilder.TYPE_KEY_DELIMITER + type;
                formatByType.put(typeKey, format);

                if (StringUtil.isNotBlank(claimPath)) {
                    DcqlQueryBuilder.ClaimSpec claimSpec = new DcqlQueryBuilder.ClaimSpec(claimPath, isOptional);
                    claimsByType
                            .computeIfAbsent(typeKey, k -> new ArrayList<>())
                            .add(claimSpec);
                }
            });

            String sdJwtUserMappingClaim = getConfig().getUserMappingClaim();
            String mdocUserMappingClaim = getConfig().getUserMappingClaimMdoc();

            for (String typeKey : formatByType.keySet()) {
                String format = formatByType.get(typeKey);
                List<DcqlQueryBuilder.ClaimSpec> claims = claimsByType.computeIfAbsent(typeKey, k -> new ArrayList<>());

                String userMappingClaim = Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(format)
                        ? mdocUserMappingClaim
                        : sdJwtUserMappingClaim;

                if (StringUtil.isNotBlank(userMappingClaim)) {
                    boolean alreadyPresent =
                            claims.stream().anyMatch(spec -> spec.path().equals(userMappingClaim));
                    if (!alreadyPresent) {
                        claims.add(new DcqlQueryBuilder.ClaimSpec(userMappingClaim, false));
                    }
                }
            }

            for (Map.Entry<String, List<DcqlQueryBuilder.ClaimSpec>> entry : claimsByType.entrySet()) {
                String typeKey = entry.getKey();
                String[] keyParts = typeKey.split("\\" + DcqlQueryBuilder.TYPE_KEY_DELIMITER, 2);
                String format = formatByType.get(typeKey);
                String type = keyParts.length > 1 ? keyParts[1] : keyParts[0];
                result.put(typeKey, new DcqlQueryBuilder.CredentialTypeSpec(format, type, entry.getValue()));
            }
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return result;
    }

    private String stripQueryParams(String uri) {
        if (uri == null) {
            return null;
        }
        int queryIndex = uri.indexOf('?');
        return queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;
    }

    private void clearSessionNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(SESSION_STATE);
        authSession.removeAuthNote(SESSION_NONCE);
        authSession.removeAuthNote(SESSION_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_REDIRECT_FLOW_RESPONSE_URI);
        authSession.removeAuthNote(SESSION_ENCRYPTION_KEY);
        authSession.removeAuthNote(SESSION_CLIENT_ID);
        authSession.removeAuthNote(SESSION_EFFECTIVE_CLIENT_ID);
        authSession.removeAuthNote("oid4vp_tab_id");
        authSession.removeAuthNote("oid4vp_client_data");
        authSession.removeAuthNote("oid4vp_session_code");
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
