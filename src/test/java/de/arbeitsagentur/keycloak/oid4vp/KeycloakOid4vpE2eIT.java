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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitForSelectorState;
import io.github.dominikschlosser.oid4vc.CredentialFormat;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakOid4vpE2eIT {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpE2eIT.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String REALM = "wallet-demo";

    private static Network network;
    private static GenericContainer<?> keycloak;
    private static Oid4vcContainer wallet;
    private static Oid4vpTestCallbackServer callback;
    private static KeycloakAdminClient adminClient;

    private static Playwright playwright;
    private static Browser browser;
    private static BrowserContext context;
    private static Page page;

    private static String kcHostUrl;
    private static String callbackUrl;

    @BeforeAll
    static void setUp() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        callbackUrl = callback.localCallbackUrl();

        network = Network.newNetwork();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.4")
                .withNetwork(network)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm")
                .withLogConsumer(
                        frame -> LOG.info("[KC] {}", frame.getUtf8String().stripTrailing()))
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)));

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        int kcMappedPort = keycloak.getMappedPort(8080);
        kcHostUrl = "http://localhost:" + kcMappedPort;

        wallet = new Oid4vcContainer("ghcr.io/dominikschlosser/oid4vc-dev:v0.13.3")
                .withHostAccess()
                .withNetwork(network)
                .withNetworkAliases("oid4vc-dev")
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-dev:8085")
                .withLogConsumer(
                        frame -> LOG.info("[OID4VC] {}", frame.getUtf8String().stripTrailing()));
        wallet.start();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
        context = browser.newContext();
        context.addInitScript("""
                const OrigES = window.EventSource;
                window.EventSource = function(url) {
                    const es = new OrigES(url);
                    es.addEventListener('ping', () => { window.__oid4vpSseReady = true; });
                    return es;
                };
                window.EventSource.prototype = OrigES.prototype;
                window.__oid4vpSseReady = false;
                """);
        page = context.newPage();

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, kcHostUrl, "admin", "admin");

        // Trust list URL must be accessible from inside Docker network
        String trustListUrl = "http://oid4vc-dev:8085/api/trustlist";
        Oid4vpTestKeycloakSetup.configureOid4vpIdentityProvider(adminClient, REALM, trustListUrl);
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, REALM, true);
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, REALM, "wallet-mock", callbackUrl);

        LOG.info("Setup complete. KC: {}, Wallet: {}", kcHostUrl, wallet.getBaseUrl());
    }

    @AfterAll
    static void tearDown() {
        if (page != null) page.close();
        if (context != null) context.close();
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
        if (keycloak != null) keycloak.stop();
        if (wallet != null) wallet.stop();
        if (network != null) network.close();
        if (callback != null) callback.close();
    }

    // ===== Tests =====

    @Test
    @Order(1)
    void loginPageShowsWalletIdpButton() {
        clearBrowserSession();

        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);
        page.waitForSelector("#username, a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstWalletLoginCreatesNewUser() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        performSameDeviceWalletLogin();

        if (page.locator("input[name='username']").count() > 0) {
            completeFirstBrokerLoginForm("wallet-user-" + System.currentTimeMillis());
        }

        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(3)
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        callback.reset();
        clearBrowserSession();

        performSameDeviceWalletLogin();

        page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        assertThat(page.url()).contains("code=");
    }

    @Test
    @Order(4)
    void mdocPresentationFlow() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, mdocDcqlQuery);

        try {
            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("mdoc-wallet-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(5)
    void crossDeviceFirstLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, true);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();

            page.waitForSelector(
                    "img[alt='QR Code for wallet login']",
                    new Page.WaitForSelectorOptions()
                            .setState(WaitForSelectorState.VISIBLE)
                            .setTimeout(30000));

            String crossDeviceWalletUrl = (String)
                    page.evaluate(
                            "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");
            assertThat(crossDeviceWalletUrl)
                    .as("Cross-device wallet URL should be present")
                    .isNotEmpty();

            LOG.info("[Test] Cross-device wallet URL: {}", crossDeviceWalletUrl);

            waitForSseConnection();

            String presentationUri = crossDeviceWalletUrl.replaceFirst("^https?://[^?]*", "openid4vp://authorize");
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Cross-device wallet response: {}", walletResponse.rawBody());

            assertThat(walletResponse.redirectUri())
                    .as("Cross-device direct_post response must not contain redirect_uri")
                    .isNull();

            try {
                page.waitForURL(
                        url -> url.contains("/complete-auth")
                                || url.contains("/first-broker-login")
                                || url.contains("/login-actions/")
                                || page.locator("input[name='username']").count() > 0
                                || url.startsWith(callbackUrl),
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
            }

            page.waitForLoadState(LoadState.NETWORKIDLE);

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("cross-device-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, false);
        }
    }

    @Test
    @Order(6)
    void crossDeviceSecondLogin() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, true);

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            page.waitForSelector(
                    "img[alt='QR Code for wallet login']",
                    new Page.WaitForSelectorOptions()
                            .setState(WaitForSelectorState.VISIBLE)
                            .setTimeout(30000));

            String crossDeviceWalletUrl = (String)
                    page.evaluate(
                            "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");

            waitForSseConnection();

            String presentationUri = crossDeviceWalletUrl.replaceFirst("^https?://[^?]*", "openid4vp://authorize");
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            assertThat(walletResponse.redirectUri())
                    .as("Cross-device direct_post response must not contain redirect_uri")
                    .isNull();

            try {
                page.waitForURL(
                        url -> url.startsWith(callbackUrl) || url.contains("code="),
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                throw new AssertionError(
                        "Cross-device second login: SSE did not navigate to callback. URL: " + page.url(), e);
            }

            assertThat(page.url())
                    .as("Second cross-device login should reach callback with auth code")
                    .satisfiesAnyOf(url -> assertThat(url).contains("code="), url -> assertThat(url)
                            .startsWith(callbackUrl));
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, false);
        }
    }

    @Test
    @Order(7)
    void credentialSetsWithSdJwtAndMdoc() throws Exception {
        callback.reset();
        clearBrowserSession();

        String credentialSetsDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid_sd_jwt",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    },
                    {
                      "id": "pid_mdoc",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ],
                  "credential_sets": [
                    {
                      "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                      "required": true
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, credentialSetsDcqlQuery);
        wallet.client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

            performSameDeviceWalletLogin();

            if (page.locator("input[name='username']").count() > 0) {
                completeFirstBrokerLoginForm("credset-mdoc-user-" + System.currentTimeMillis());
            }

            assertThat(page.url()).contains("code=");
        } finally {
            wallet.client().clearPreferredFormat();
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(8)
    void revokedCredentialIsRejected() throws Exception {
        callback.reset();
        clearBrowserSession();

        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        // Get credential ID and revoke it
        var credentials = wallet.client().getCredentials();
        assertThat(credentials).as("Wallet should have at least one credential").isNotEmpty();
        String credentialId = credentials.get(0).id();
        wallet.client().revokeCredential(credentialId);

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Revoked credential wallet response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(2000);
            String bodyText = page.locator("body").textContent().toLowerCase();
            boolean hasError = bodyText.contains("error")
                    || bodyText.contains("revoked")
                    || bodyText.contains("failed")
                    || bodyText.contains("denied");

            assertThat(hasError)
                    .as(
                            "Revoked credential should be rejected. URL: %s, Body: %s",
                            page.url(), bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
        } finally {
            wallet.client().unrevokeCredential(credentialId);
        }
    }

    @Test
    @Order(9)
    void walletErrorShowsErrorAndAllowsRetry() throws Exception {
        callback.reset();
        clearBrowserSession();

        wallet.client().setNextError("access_denied", "User denied consent");

        try {
            page.navigate(buildAuthRequestUri().toString());
            page.waitForLoadState(LoadState.NETWORKIDLE);

            page.locator("a#social-oid4vp").click();
            waitForOpenWalletLink();

            String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
            String presentationUri = convertToOpenid4vpUri(walletUrl);
            PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

            LOG.info("[Test] Wallet error response: {}", walletResponse.rawBody());

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState(LoadState.NETWORKIDLE);
            }

            Thread.sleep(2000);
            String bodyText = page.locator("body").textContent().toLowerCase();
            boolean hasError = bodyText.contains("error")
                    || bodyText.contains("denied")
                    || bodyText.contains("cancelled")
                    || bodyText.contains("failed");

            assertThat(hasError)
                    .as(
                            "Error page should be shown. URL: %s, Body: %s",
                            page.url(), bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
        } finally {
            wallet.client().clearNextError();
        }
    }

    // ===== Same-Device Flow Helper =====

    private void performSameDeviceWalletLogin() throws Exception {
        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);

        page.locator("a#social-oid4vp").click();
        waitForOpenWalletLink();

        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl).as("Wallet URL should be present").isNotEmpty();

        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse walletResponse = wallet.acceptPresentationRequest(presentationUri);

        LOG.info("[Test] Wallet response: {}", walletResponse.rawBody());

        String redirectUri = walletResponse.redirectUri();

        // The wallet POSTs directly (not through the browser), so the server stores a
        // completion signal. The SSE listener in the page may navigate the browser
        // automatically. Wait briefly for SSE-driven navigation before falling back to
        // manual redirect_uri navigation.
        boolean sseNavigated = false;
        try {
            page.waitForURL(
                    url -> url.startsWith(callbackUrl)
                            || url.contains("/first-broker-login")
                            || url.contains("/login-actions/")
                            || url.contains("/complete-auth")
                            || page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(10000));
            sseNavigated = true;
            LOG.info("[Test] SSE navigated browser to: {}", page.url());
        } catch (Exception ignored) {
            LOG.info("[Test] SSE did not navigate within timeout, falling back to manual redirect");
        }

        if (!sseNavigated && redirectUri != null) {
            LOG.info("[Test] Navigating to redirect_uri: {}", redirectUri);
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        try {
            page.waitForURL(
                    url -> url.startsWith(callbackUrl)
                            || url.contains("/first-broker-login")
                            || url.contains("/login-actions/")
                            || page.locator("input[name='username']").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = "";
            try {
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {
            }
            throw new AssertionError(
                    "Unexpected state after wallet login. URL: " + page.url() + "\nWallet response: "
                            + walletResponse.rawBody() + "\nRedirect URI: " + redirectUri + "\nPage content: "
                            + bodyText.substring(0, Math.min(1000, bodyText.length())),
                    e);
        }
    }

    private String convertToOpenid4vpUri(String walletUrl) {
        if (walletUrl.startsWith("openid4vp://")) {
            return walletUrl;
        }
        return walletUrl.replace(wallet.getAuthorizeUrl() + "?", "openid4vp://authorize?");
    }

    // ===== Test Helper Methods =====

    private static void waitForSseConnection() {
        page.waitForCondition(
                () -> {
                    Object ready = page.evaluate("() => window.__oid4vpSseReady === true");
                    return Boolean.TRUE.equals(ready);
                },
                new Page.WaitForConditionOptions().setTimeout(10000));
        LOG.info("[Test] SSE connection established (first ping received)");
    }

    private static void waitForOpenWalletLink() {
        page.waitForSelector(
                "a:has-text('Open Wallet App')",
                new Page.WaitForSelectorOptions()
                        .setState(WaitForSelectorState.VISIBLE)
                        .setTimeout(30000));
    }

    private void completeFirstBrokerLoginForm(String uniqueUsername) {
        page.waitForLoadState(LoadState.NETWORKIDLE);
        Locator usernameFields = page.locator("input[name='username']");
        if (usernameFields.count() > 0 && usernameFields.first().inputValue().isEmpty()) {
            usernameFields.first().fill(uniqueUsername);
        }
        Locator emailFields = page.locator("input[name='email']");
        if (emailFields.count() > 0 && emailFields.first().inputValue().isEmpty()) {
            emailFields.first().fill(uniqueUsername + "@example.com");
        }
        Locator firstNameFields = page.locator("input[name='firstName']");
        if (firstNameFields.count() > 0 && firstNameFields.first().inputValue().isEmpty()) {
            firstNameFields.first().fill("Test");
        }
        Locator lastNameFields = page.locator("input[name='lastName']");
        if (lastNameFields.count() > 0 && lastNameFields.first().inputValue().isEmpty()) {
            lastNameFields.first().fill("User");
        }

        page.locator("input[type='submit'], button[type='submit']").first().click();
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = "";
            try {
                bodyText = page.locator("body").textContent();
            } catch (Exception ignored) {
            }
            throw new AssertionError(
                    "First broker login form did not redirect to callback. URL: " + page.url() + "\nPage content: "
                            + bodyText.substring(0, Math.min(2000, bodyText.length())),
                    e);
        }
    }

    private void clearBrowserSession() {
        context.clearCookies();
        try {
            page.navigate(kcHostUrl + "/realms/" + REALM + "/", new Page.NavigateOptions().setTimeout(10000));
        } catch (Exception e) {
            LOG.warn("Initial navigation failed: {}", e.getMessage());
            try {
                page.navigate("about:blank");
            } catch (Exception ignored) {
            }
        }
        try {
            page.evaluate("() => { window.localStorage.clear(); window.sessionStorage.clear(); }");
        } catch (Exception ignored) {
        }
        context.clearCookies();
    }

    private URI buildAuthRequestUri() {
        String state = "s-" + System.nanoTime();
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String codeChallenge;
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String uri = kcHostUrl + "/realms/" + REALM + "/protocol/openid-connect/auth" + "?client_id=wallet-mock"
                + "&redirect_uri=" + urlEncode(callbackUrl)
                + "&response_type=code"
                + "&scope=openid"
                + "&state=" + urlEncode(state)
                + "&code_challenge=" + urlEncode(codeChallenge)
                + "&code_challenge_method=S256";
        return URI.create(uri);
    }

    private static String buildDefaultDcqlQuery() {
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

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void copyRealmImport() {
        Path realmExport = Path.of("src/test/resources/realm-export.json").toAbsolutePath();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport), "/opt/keycloak/data/import/realm-export.json");
    }

    private static void copyProviderJars() throws IOException {
        Path providerJar = findProviderJar();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(providerJar), "/opt/keycloak/providers/" + providerJar.getFileName());

        Path deps = Path.of("target/providers").toAbsolutePath();
        if (!Files.isDirectory(deps)) {
            return;
        }
        try (Stream<Path> stream = Files.list(deps)) {
            for (Path jar : stream.filter(p -> p.getFileName().toString().endsWith(".jar"))
                    .toList()) {
                keycloak.withCopyFileToContainer(
                        MountableFile.forHostPath(jar), "/opt/keycloak/providers/" + jar.getFileName());
            }
        }
    }

    private static Path findProviderJar() throws IOException {
        Path target = Path.of("target").toAbsolutePath();
        try (Stream<Path> stream = Files.list(target)) {
            return stream.filter(path -> path.getFileName().toString().startsWith("keycloak-extension-wallet-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Provider jar not found in target/"));
        }
    }
}
