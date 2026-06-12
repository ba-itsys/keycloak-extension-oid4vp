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
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectPlaywrightBrowser;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestApp;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestApp;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
    private static final String SSE_INIT_SCRIPT = """
            const OrigES = window.EventSource;
            window.EventSource = function(url) {
                window.__oid4vpStatusUrl = url;
                const es = new OrigES(url);
                es.addEventListener('ping', () => { window.__oid4vpSseReady = true; });
                return es;
            };
            window.EventSource.prototype = OrigES.prototype;
            window.__oid4vpSseReady = false;
            window.__oid4vpStatusUrl = null;
            """;

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
        ensureIdentityProviderConfigured();
        context = newBrowserContext();
        page = context.newPage();
        flow = flowFor(wallet());
    }

    /**
     * Creates the OID4VP identity provider pointing at the injected wallet's trust list. The
     * realm has CLASS lifecycle, so this runs once per test class.
     */
    private void ensureIdentityProviderConfigured() {
        boolean exists = realm.admin().identityProviders().findAll().stream()
                .anyMatch(idp -> Oid4vpTestKeycloakSetup.IDP_ALIAS.equals(idp.getAlias()));
        if (exists) {
            return;
        }
        String haipCertPem = TestCertificates.generateHaipCertificateChainPem();
        try (Response response = realm.admin()
                .identityProviders()
                .create(Oid4vpTestKeycloakSetup.defaultIdentityProvider(wallet().pidTrustListUrl(), haipCertPem))) {
            assertThat(response.getStatus())
                    .as("Creating the OID4VP identity provider failed: %s", response.readEntity(String.class))
                    .isEqualTo(201);
        }
        try (Response response = realm.admin()
                .identityProviders()
                .get(Oid4vpTestKeycloakSetup.IDP_ALIAS)
                .addMapper(Oid4vpTestKeycloakSetup.defaultSessionNoteMapper())) {
            assertThat(response.getStatus())
                    .as("Creating the OID4VP identity provider mapper failed: %s", response.readEntity(String.class))
                    .isEqualTo(201);
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
        BrowserContext browserContext = browser.newContext();
        browserContext.addInitScript(SSE_INIT_SCRIPT);
        return browserContext;
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
            String requestHandle = flow.getRequestHandle();
            if (requestHandle == null || requestHandle.isBlank()) {
                throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
            }
            String completeAuthUrl = keycloakUrls.getBase() + "/realms/" + REALM
                    + "/broker/oid4vp/endpoint/complete-auth?request_handle="
                    + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
            page.navigate(completeAuthUrl);
        }
        page.waitForLoadState();
    }

    protected void assertLoginFailed(Oid4vpLoginFlowHelper.WalletResponse walletResponse, String... expectedSnippets) {
        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState();
            String bodyText = normalizedBodyText();
            assertThat(flow.isCallbackUrl(page.url()))
                    .as("Login should not succeed")
                    .isFalse();
            assertThat(bodyText).as("Expected an error page").containsAnyOf(expectedSnippets);
            return;
        }

        assertThat(flow.isCallbackUrl(page.url()))
                .as("Login should not succeed")
                .isFalse();
        String walletResponseText = normalizedWalletResponseText(walletResponse.rawBody());
        assertThat(walletResponseText)
                .as("Expected wallet-visible error response when no redirect_uri is returned")
                .containsAnyOf(expectedSnippets);
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
            String renderedFailureText;
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState();
                renderedFailureText = waitForErrorPageContent(Duration.ofSeconds(10));
            } else {
                renderedFailureText = normalizedWalletResponseText(walletResponse.rawBody());
            }

            boolean hasError = containsErrorSnippet(renderedFailureText);
            assertThat(hasError)
                    .as(
                            "Revoked %s credential should be rejected. URL: %s, Wallet response: %s, Failure text: %s",
                            formatLabel,
                            page.url(),
                            walletResponse.rawBody(),
                            renderedFailureText.substring(0, Math.min(500, renderedFailureText.length())))
                    .isTrue();
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }
    }

    private String waitForErrorPageContent(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        String lastBodyText = "";
        while (System.nanoTime() < deadline) {
            lastBodyText = normalizedBodyText();
            if (containsErrorSnippet(lastBodyText)) {
                return lastBodyText;
            }
            Thread.sleep(200);
        }
        return lastBodyText;
    }

    private String normalizedBodyText() {
        String bodyText = page.locator("body").textContent();
        return bodyText == null ? "" : bodyText.toLowerCase(Locale.ROOT);
    }

    private String normalizedWalletResponseText(String rawBody) {
        if (rawBody == null || rawBody.isBlank()) {
            return "";
        }
        StringBuilder combined = new StringBuilder(rawBody);
        try {
            JsonNode root = OBJECT_MAPPER.readTree(rawBody);
            appendTextualFields(root, combined);
            JsonNode nestedBody = root.path("response").path("body");
            if (nestedBody.isTextual()) {
                combined.append('\n').append(nestedBody.asText());
                try {
                    JsonNode nestedJson = OBJECT_MAPPER.readTree(nestedBody.asText());
                    appendTextualFields(nestedJson, combined);
                } catch (Exception ignored) {
                    // Keep the raw nested response body when it is not JSON.
                }
            }
        } catch (Exception ignored) {
            // Keep the raw wallet response body when it is not JSON.
        }
        return combined.toString().toLowerCase(Locale.ROOT);
    }

    private void appendTextualFields(JsonNode node, StringBuilder combined) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.isTextual()) {
            combined.append('\n').append(node.asText());
            return;
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> appendTextualFields(entry.getValue(), combined));
            return;
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                appendTextualFields(child, combined);
            }
        }
    }

    private static boolean containsErrorSnippet(String bodyText) {
        return bodyText.contains("error")
                || bodyText.contains("revoked")
                || bodyText.contains("failed")
                || bodyText.contains("denied");
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

    protected static String buildDefaultDcqlQuery() {
        return """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;
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

    protected static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
