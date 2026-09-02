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
package de.arbeitsagentur.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.options.Cookie;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectPlaywrightBrowser;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestApp;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestApp;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.events.EventType;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.server.KeycloakUrls;

// @KeycloakIntegrationTest is not @Inherited and the framework ignores it on an abstract base
// class, so it and the injection annotations for class specific resources such as the wallet live
// on the concrete test classes.
abstract class AbstractOid4vpE2eTest {

    static final String REALM = Oid4vpRealmConfig.REALM;
    static final String CLIENT_ID = Oid4vpRealmConfig.CLIENT_ID;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // StatusListVerifier rejects a revoked credential with "Credential has been revoked (status=...)"
    // and the endpoint records that message as the error_description of the login error event.
    // Matching on "revoked" ties the assertion to the revocation check instead of any failure.
    private static final String[] REVOCATION_ERROR_SNIPPETS = {"revoked"};

    @InjectRealm(config = Oid4vpRealmConfig.class)
    protected ManagedRealm realm;

    @InjectKeycloakUrls
    protected KeycloakUrls keycloakUrls;

    @InjectTestApp
    protected TestApp app;

    @InjectPlaywrightBrowser
    protected Browser browser;

    protected BrowserContext context;
    protected Page page;
    protected Oid4vpLoginFlowHelper flow;

    protected abstract TestWallet wallet();

    @BeforeEach
    void setUpTestEnvironment() {
        // The realm outlives a single test and so do its login events, so clearing them ties the
        // failure cause assertions to the login this test drove. It also means these classes cannot
        // run in parallel against the shared realm.
        realm.admin().clearEvents();
        ensureIdentityProviderConfigured();
        context = newBrowserContext();
        page = context.newPage();
        flow = flowFor(wallet());
    }

    /**
     * Creates the OID4VP identity provider pointing at the injected wallet's trust list. Because the
     * realm has CLASS lifecycle the provider is created once per test class, and since the framework
     * restores neither the mappers nor the credential sets that reference them, this resets both to
     * the defaults before every test. Config changes made through {@link #setIdpConfig(Map)} are
     * restored by the framework itself.
     */
    private void ensureIdentityProviderConfigured() {
        boolean trustIdpExists = realm.admin().identityProviders().findAll().stream()
                .anyMatch(idp -> Oid4vpTestKeycloakSetup.TRUST_IDP_ALIAS.equals(idp.getAlias()));
        if (!trustIdpExists) {
            try (Response response = realm.admin()
                    .identityProviders()
                    .create(Oid4vpTestKeycloakSetup.defaultTrustListIdentityProvider(wallet().pidTrustListUrl()))) {
                assertThat(response.getStatus())
                        .as("Creating the trust list identity provider failed: %s", response.readEntity(String.class))
                        .isEqualTo(201);
            }
        }
        boolean exists = realm.admin().identityProviders().findAll().stream()
                .anyMatch(idp -> Oid4vpTestKeycloakSetup.IDP_ALIAS.equals(idp.getAlias()));
        if (!exists) {
            String haipCertPem = TestCertificates.generateHaipCertificateChainPem();
            try (Response response = realm.admin()
                    .identityProviders()
                    .create(Oid4vpTestKeycloakSetup.defaultIdentityProvider(haipCertPem))) {
                assertThat(response.getStatus())
                        .as("Creating the OID4VP identity provider failed: %s", response.readEntity(String.class))
                        .isEqualTo(201);
            }
        }
        resetIdpMappersToDefault();
    }

    private void resetIdpMappersToDefault() {
        List<IdentityProviderMapperRepresentation> defaults = new ArrayList<>();
        defaults.add(Oid4vpTestKeycloakSetup.defaultSessionNoteMapper());
        defaults.addAll(Oid4vpTestKeycloakSetup.defaultDcqlMappers());
        replaceIdpMappers(defaults);
        resetSubjectCredentialSettings();
    }

    /**
     * Restores the credential sets and the settings validated against them in a single update,
     * because a configuration that expects the subject credential to be missing has to name it and
     * clearing one without the other is refused on save.
     */
    private void resetSubjectCredentialSettings() {
        IdentityProviderResource idp = realm.admin().identityProviders().get(Oid4vpTestKeycloakSetup.IDP_ALIAS);
        IdentityProviderRepresentation representation = idp.toRepresentation();
        representation
                .getConfig()
                .put(
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SETS,
                        Oid4vpTestKeycloakSetup.alternativeCredentialSets(
                                Oid4vpTestKeycloakSetup.SD_JWT_PID_CREDENTIAL_ID,
                                Oid4vpTestKeycloakSetup.MDOC_PID_CREDENTIAL_ID));
        representation
                .getConfig()
                .put(
                        Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES,
                        Oid4vpTestKeycloakSetup.defaultPrincipalAttributeIds());
        representation.getConfig().remove(Oid4vpIdentityProviderConfig.ALLOW_MISSING_SUBJECT_CREDENTIAL);
        idp.update(representation);
    }

    /**
     * Replaces the identity provider mappers that carry a credential type and keeps the untyped
     * ones, narrowing the credential sets and principal attributes to the credentials the new
     * mappers produce, because naming a credential no mapper produces is refused on save.
     */
    protected void replaceDcqlMappers(List<IdentityProviderMapperRepresentation> mappers) {
        IdentityProviderResource idp = realm.admin().identityProviders().get(Oid4vpTestKeycloakSetup.IDP_ALIAS);
        for (IdentityProviderMapperRepresentation existing : idp.getMappers()) {
            String credentialType =
                    existing.getConfig() != null ? existing.getConfig().get("credential.type") : null;
            if (credentialType != null && !credentialType.isBlank()) {
                idp.delete(existing.getId());
            }
        }
        addIdpMappers(idp, mappers);
        String[] credentialIds =
                Oid4vpTestKeycloakSetup.credentialIdsOf(mappers).toArray(String[]::new);
        IdentityProviderRepresentation representation = idp.toRepresentation();
        representation
                .getConfig()
                .put(
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SETS,
                        Oid4vpTestKeycloakSetup.alternativeCredentialSets(credentialIds));
        representation
                .getConfig()
                .put(
                        Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES,
                        Oid4vpTestKeycloakSetup.principalAttributesFor(credentialIds));
        idp.update(representation);
    }

    /**
     * Applies a DCQL {@code credential_sets} configuration to the OID4VP identity provider. The
     * framework does not restore this write; {@link #ensureIdentityProviderConfigured()} puts the
     * default credential sets back before the next test.
     */
    protected void setCredentialSets(String credentialSetsJson) {
        IdentityProviderResource idp = realm.admin().identityProviders().get(Oid4vpTestKeycloakSetup.IDP_ALIAS);
        IdentityProviderRepresentation representation = idp.toRepresentation();
        representation.getConfig().put(Oid4vpIdentityProviderConfig.CREDENTIAL_SETS, credentialSetsJson);
        idp.update(representation);
    }

    private void replaceIdpMappers(List<IdentityProviderMapperRepresentation> mappers) {
        IdentityProviderResource idp = realm.admin().identityProviders().get(Oid4vpTestKeycloakSetup.IDP_ALIAS);
        for (IdentityProviderMapperRepresentation existing : idp.getMappers()) {
            idp.delete(existing.getId());
        }
        addIdpMappers(idp, mappers);
    }

    protected void addIdpMapper(IdentityProviderMapperRepresentation mapper) {
        addIdpMappers(realm.admin().identityProviders().get(Oid4vpTestKeycloakSetup.IDP_ALIAS), List.of(mapper));
    }

    private void addIdpMappers(IdentityProviderResource idp, List<IdentityProviderMapperRepresentation> mappers) {
        for (IdentityProviderMapperRepresentation mapper : mappers) {
            try (Response response = idp.addMapper(mapper)) {
                assertThat(response.getStatus())
                        .as(
                                "Creating identity provider mapper '%s' failed: %s",
                                mapper.getName(), response.readEntity(String.class))
                        .isEqualTo(201);
            }
        }
    }

    @AfterEach
    void closeBrowserContext() {
        wallet().resetState();
        if (page != null) {
            page.close();
        }
        if (context != null) {
            context.close();
        }
    }

    protected BrowserContext newBrowserContext() {
        return browser.newContext();
    }

    protected Oid4vpLoginFlowHelper flowFor(TestWallet testWallet) {
        return new Oid4vpLoginFlowHelper(page, context, testWallet, keycloakUrls.getBase(), app, CLIENT_ID, REALM);
    }

    protected TestApp testApp() {
        return app;
    }

    protected ObjectMapper objectMapper() {
        return OBJECT_MAPPER;
    }

    /**
     * Updates the OID4VP identity provider config. The framework restores the original configuration
     * after the test, so apply all changes of a test in a single call to keep the restore order
     * correct.
     */
    protected void setIdpConfig(Map<String, String> entries) {
        realm.updateIdentityProvider(
                Oid4vpTestKeycloakSetup.IDP_ALIAS, idp -> idp.getConfig().putAll(entries));
    }

    /** Updates the ETSI trust list identity provider config, which the framework restores afterwards. */
    protected void setTrustIdpConfig(Map<String, String> entries) {
        realm.updateIdentityProvider(
                Oid4vpTestKeycloakSetup.TRUST_IDP_ALIAS, idp -> idp.getConfig().putAll(entries));
    }

    protected void deleteAllOid4vpUsers() {
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(realm.admin());
    }

    protected int countOid4vpUsers() {
        return Oid4vpTestKeycloakSetup.countOid4vpUsers(realm.admin());
    }

    protected void performSameDeviceLogin(String usernamePrefix) throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded(usernamePrefix);
    }

    /** Starts a same device login and returns the request object the wallet would fetch. */
    protected SignedJWT fetchCurrentRequestObject() throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        return fetchRequestObject(flow.getSameDeviceWalletUrl());
    }

    /**
     * Fetches the request object behind a wallet URL of a login already in progress. Fetching it does
     * not consume the request context, so the wallet can still be driven through the same URL.
     */
    protected SignedJWT fetchRequestObject(String walletUrl) throws Exception {
        HttpResponse<String> response = requestObjectResponse(walletUrl);
        assertThat(response.statusCode()).isEqualTo(200);
        return SignedJWT.parse(response.body());
    }

    protected HttpResponse<String> requestObjectResponse(String walletUrl) throws Exception {
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        return HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    protected void waitForCrossDeviceNavigation() {
        try {
            page.waitForURL(
                    url -> url.contains("/complete-auth")
                            || url.contains("/first-broker-login")
                            || url.contains("/login-actions/")
                            || page.locator("input[name='username']").count() > 0
                            || flow.isCallbackUrl(url),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            // The complete-auth URL carries a single-use response_code that only the SSE 'complete'
            // event delivers to the browser, so the test cannot build the URL itself and a browser
            // that never navigated means the cross-device login cannot complete.
            throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
        }
        page.waitForLoadState();
    }

    /**
     * Asserts the login was rejected for the expected cause. The snippets have to name that cause
     * specifically, so that a login failing for an unrelated reason does not satisfy the assertion.
     */
    protected void assertLoginFailed(Oid4vpLoginFlowHelper.WalletResponse walletResponse, String... expectedSnippets) {
        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState();
        }
        assertThat(flow.isCallbackUrl(page.url()))
                .as("Login should not succeed")
                .isFalse();
        assertLoginFailedBecauseOf(expectedSnippets);
    }

    /**
     * Asserts the newest login error event names one of the expected causes as its
     * {@code error_description}. {@code EventBuilder.error} stores the event in its own transaction,
     * so it is readable as soon as the wallet has been answered.
     */
    protected void assertLoginFailedBecauseOf(String... expectedSnippets) {
        assertThat(newestLoginErrorDescription())
                .as("Expected the newest login error event to name the failure cause")
                .isNotNull()
                .containsAnyOf(expectedSnippets);
    }

    private String newestLoginErrorDescription() {
        return realm
                .admin()
                .getEvents(List.of(EventType.LOGIN_ERROR.name()), null, null, null, null, null, null, null)
                .stream()
                .map(EventRepresentation::getDetails)
                .filter(Objects::nonNull)
                .map(details -> details.get(OAuth2Constants.ERROR_DESCRIPTION))
                .filter(Objects::nonNull)
                .findFirst()
                .map(description -> description.toLowerCase(Locale.ROOT))
                .orElse(null);
    }

    protected void assertRevokedCredentialIsRejected(String formatLabel) throws Exception {
        assertRevokedCredentialIsRejected(formatLabel, null);
    }

    protected void assertRevokedCredentialIsRejected(String formatLabel, String credentialType) throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String credentialId;
        if (credentialType != null) {
            var typedCredentials = wallet().client().getCredentialsByType(credentialType);
            assertThat(typedCredentials)
                    .as("Wallet should have a credential of type %s", credentialType)
                    .isNotEmpty();
            credentialId = typedCredentials.get(0).id();
        } else {
            var credentials = wallet().client().getCredentials();
            assertThat(credentials)
                    .as("Wallet should have at least one credential")
                    .isNotEmpty();
            credentialId = credentials.get(0).id();
        }
        wallet().client().revokeCredential(credentialId);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);

            String redirectUri = walletResponse.redirectUri();
            assertThat(redirectUri)
                    .as("A rejected %s presentation has to hand the End-User back to the front channel", formatLabel)
                    .isNotNull();

            page.navigate(redirectUri);
            page.waitForLoadState();
            assertThat(flow.isCallbackUrl(page.url()))
                    .as("A revoked %s credential must not complete the login. URL: %s", formatLabel, page.url())
                    .isFalse();

            assertLoginFailedBecauseOf(REVOCATION_ERROR_SNIPPETS);
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }
    }

    protected String extractRedirectUriFromSseResponse(String sseBody) throws IOException {
        for (String rawLine : sseBody.split("\\R")) {
            String line = rawLine.stripLeading();
            if (line.startsWith("data:")) {
                String payloadJson = line.length() > 5 && line.charAt(5) == ' ' ? line.substring(6) : line.substring(5);
                @SuppressWarnings("unchecked")
                Map<String, Object> payload = OBJECT_MAPPER.readValue(payloadJson, Map.class);
                Object redirectUri = payload.get("redirect_uri");
                if (redirectUri != null) {
                    return String.valueOf(redirectUri);
                }
            }
        }
        throw new IllegalArgumentException("No redirect_uri found in SSE response: " + sseBody);
    }

    protected String browserCookieHeader(String url) {
        List<Cookie> cookies = context.cookies(url);
        if (cookies.isEmpty()) {
            return "";
        }
        return cookies.stream()
                .map(cookie -> cookie.name + "=" + cookie.value)
                .reduce((a, b) -> a + "; " + b)
                .orElse("");
    }

    protected static String extractQueryParam(String uri, String name) {
        String query = uri.contains("?") ? uri.substring(uri.indexOf('?') + 1) : uri;
        for (String param : query.split("&")) {
            if (param.startsWith(name + "=")) {
                return URLDecoder.decode(param.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalArgumentException("No query parameter named " + name + " found in " + uri);
    }

    protected JsonNode exchangeAuthorizationCode() throws Exception {
        assertThat(testApp().lastCallbackUri())
                .as("Expected login callback with authorization code")
                .isNotNull();

        HttpResponse<String> response = testApp().exchangeAuthorizationCode(keycloakUrls.getToken(REALM), CLIENT_ID);

        assertThat(response.statusCode())
                .withFailMessage("Token exchange failed: status=%d body=%s", response.statusCode(), response.body())
                .isEqualTo(200);
        return OBJECT_MAPPER.readTree(response.body());
    }

    protected SignedJWT idTokenOfCompletedLogin() throws Exception {
        String serializedIdToken = exchangeAuthorizationCode().path("id_token").asText();
        assertThat(serializedIdToken).isNotBlank();
        return SignedJWT.parse(serializedIdToken);
    }

    protected String encryptWalletResponse(ECKey publicKey, Map<String, Object> payload) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID())
                        .build(),
                new Payload(OBJECT_MAPPER.writeValueAsString(payload)));
        jwe.encrypt(new ECDHEncrypter(publicKey));
        return jwe.serialize();
    }

    protected String responseUri() {
        return keycloakUrls.getBase() + "/realms/" + REALM + "/broker/" + Oid4vpTestKeycloakSetup.IDP_ALIAS
                + "/endpoint";
    }

    protected static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
