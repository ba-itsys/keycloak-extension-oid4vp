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

// @KeycloakIntegrationTest and the injection annotations for class specific resources such as the
// wallet live on the concrete test classes. @KeycloakIntegrationTest is not @Inherited and the
// framework ignores it on an abstract base class.
abstract class AbstractOid4vpE2eTest {

    static final String REALM = Oid4vpRealmConfig.REALM;
    static final String CLIENT_ID = Oid4vpRealmConfig.CLIENT_ID;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // A revoked credential is rejected with "Credential has been revoked (status=...)"
    // (StatusListVerifier), which the endpoint records as the error_description of the login error
    // event. Matching on "revoked" ties the rejection to the revocation check instead of accepting
    // any failure.
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

    // The wallet injected by the concrete test class
    protected abstract TestWallet wallet();

    @BeforeEach
    void setUpTestEnvironment() {
        // The realm outlives a single test, so its login events do too. Clearing them keeps a
        // failure cause assertion tied to the login the test itself drove, which also means these
        // classes cannot run in parallel against the shared realm.
        realm.admin().clearEvents();
        ensureIdentityProviderConfigured();
        context = newBrowserContext();
        page = context.newPage();
        flow = flowFor(wallet());
    }

    /**
     * Creates the OID4VP identity provider pointing at the injected wallet's trust list. The
     * realm has CLASS lifecycle, so the provider is created once per test class while the mappers
     * and the credential sets that reference them are reset to the defaults before every test
     * (neither is restored by the framework, unlike identity provider config changes made through
     * {@link #setIdpConfig(Map)}).
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
     * Restores the credential sets and the settings that are validated against them in one update.
     * They have to travel together: a configuration that expects the subject credential to be
     * missing has to name it, so clearing one without the other is refused when it is saved.
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
     * Replaces the DCQL-driving identity provider mappers (those with a credential type) while
     * keeping untyped mappers, and narrows the credential sets to the credentials these mappers
     * produce so no set references a credential that is not configured. The next test starts
     * from the default mapper set again.
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
        // The credential sets and the credentials carrying the subject travel together: naming a
        // credential no mapper produces is refused when it is saved.
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
     * framework does not restore this write, so every test starts from the default credential sets
     * again through {@link #ensureIdentityProviderConfigured()}.
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
     * Updates the OID4VP identity provider config. The framework restores the original
     * configuration after the test. Apply all changes of a test in a single call so the restore
     * order is correct.
     */
    protected void setIdpConfig(Map<String, String> entries) {
        realm.updateIdentityProvider(
                Oid4vpTestKeycloakSetup.IDP_ALIAS, idp -> idp.getConfig().putAll(entries));
    }

    /**
     * Updates the ETSI trust list identity provider config. The framework restores the original
     * configuration after the test.
     */
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
     * Fetches the request object of a wallet URL of a login already in progress. Retrieval does not
     * consume the request context, so the wallet can still be driven through the same wallet URL.
     */
    protected SignedJWT fetchRequestObject(String walletUrl) throws Exception {
        HttpResponse<String> response = requestObjectResponse(walletUrl);
        assertThat(response.statusCode()).isEqualTo(200);
        return SignedJWT.parse(response.body());
    }

    /** The answer a wallet gets when it fetches the request object a wallet URL points at. */
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
            // The complete-auth URL carries a single-use response_code that is delivered to the
            // browser only via the SSE 'complete' event, so it cannot be reconstructed manually.
            // If the SSE never navigated the browser, the cross-device login genuinely cannot complete.
            throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
        }
        page.waitForLoadState();
    }

    /**
     * Asserts the login was rejected for the expected cause. The snippets must name that cause
     * specifically, so a login that fails for an unrelated reason does not satisfy this assertion.
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
     * {@code error_description}. {@code EventBuilder.error} stores the event in its own
     * transaction, so it is readable as soon as the wallet has been answered.
     */
    protected void assertLoginFailedBecauseOf(String... expectedSnippets) {
        assertThat(newestLoginErrorDescription())
                .as("Expected the newest login error event to name the failure cause")
                .isNotNull()
                .containsAnyOf(expectedSnippets);
    }

    /** The {@code error_description} of the realm's newest login error event, lower cased. */
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

    protected String encryptWalletResponse(ECKey publicKey, Map<String, Object> payload) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID())
                        .build(),
                new Payload(OBJECT_MAPPER.writeValueAsString(payload)));
        jwe.encrypt(new ECDHEncrypter(publicKey));
        return jwe.serialize();
    }

    /** The response URI the wallet posts its authorization response to. */
    protected String responseUri() {
        return keycloakUrls.getBase() + "/realms/" + REALM + "/broker/" + Oid4vpTestKeycloakSetup.IDP_ALIAS
                + "/endpoint";
    }

    protected static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
