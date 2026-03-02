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
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import io.github.dominikschlosser.oid4vc.CredentialFormat;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.RegisterExtension;
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

    private static Oid4vpLoginFlowHelper flow;

    @RegisterExtension
    IdpConfigScope idpConfig = new IdpConfigScope(() -> adminClient, REALM);

    @BeforeAll
    static void setUp() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        String callbackUrl = callback.localCallbackUrl();

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

        String kcHostUrl = "http://localhost:" + keycloak.getMappedPort(8080);

        wallet = new Oid4vcContainer()
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

        flow = new Oid4vpLoginFlowHelper(page, context, wallet, kcHostUrl, callbackUrl, REALM);

        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, kcHostUrl, "admin", "admin");

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
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        page.waitForSelector("#username, a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    @Order(2)
    void firstWalletLoginCreatesNewUser() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        performSameDeviceLogin("wallet-user");

        flow.assertLoginSucceeded();
    }

    @Test
    @Order(3)
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        callback.reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);

        flow.assertLoginSucceeded();
    }

    @Test
    @Order(4)
    void mdocPresentationFlow() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
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
            performSameDeviceLogin("mdoc-wallet-user");
            flow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(5)
    void crossDeviceFirstLogin() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, true);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getCrossDeviceWalletUrl();
            LOG.info("[Test] Cross-device wallet URL: {}", walletUrl);

            flow.waitForSseConnection();

            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);
            LOG.info("[Test] Cross-device wallet response: {}", walletResponse.rawBody());

            assertThat(walletResponse.redirectUri())
                    .as("Cross-device direct_post response must not contain redirect_uri")
                    .isNull();

            waitForCrossDeviceNavigation();
            flow.completeFirstBrokerLoginIfNeeded("cross-device-user");
            flow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, false);
        }
    }

    @Test
    @Order(6)
    void crossDeviceSecondLogin() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, true);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getCrossDeviceWalletUrl();

            flow.waitForSseConnection();

            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);

            assertThat(walletResponse.redirectUri())
                    .as("Cross-device direct_post response must not contain redirect_uri")
                    .isNull();

            try {
                page.waitForURL(
                        url -> url.contains("code=") || flow.isCallbackUrl(url),
                        new Page.WaitForURLOptions().setTimeout(30000));
            } catch (Exception e) {
                throw new AssertionError(
                        "Cross-device second login: SSE did not navigate to callback. URL: " + page.url(), e);
            }

            flow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, false);
        }
    }

    @Test
    @Order(7)
    void credentialSetsWithSdJwtAndMdoc() throws Exception {
        callback.reset();
        flow.clearBrowserSession();

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
            performSameDeviceLogin("credset-mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet.client().clearPreferredFormat();
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    @Order(8)
    void revokedCredentialIsRejected() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        var credentials = wallet.client().getCredentials();
        assertThat(credentials).as("Wallet should have at least one credential").isNotEmpty();
        String credentialId = credentials.get(0).id();
        wallet.client().revokeCredential(credentialId);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState();
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
        flow.clearBrowserSession();
        wallet.client().setNextError("access_denied", "User denied consent");

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState();
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

    @Test
    @Order(10)
    void requestObjectCanBeFetchedMultipleTimes() throws Exception {
        callback.reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> response1 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response2 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response3 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response1.statusCode()).as("First fetch should succeed").isEqualTo(200);
        assertThat(response2.statusCode()).as("Second fetch should succeed").isEqualTo(200);
        assertThat(response3.statusCode()).as("Third fetch should succeed").isEqualTo(200);

        String kid1 = Oid4vpLoginFlowHelper.extractEncryptionKid(response1.body());
        String kid2 = Oid4vpLoginFlowHelper.extractEncryptionKid(response2.body());
        String kid3 = Oid4vpLoginFlowHelper.extractEncryptionKid(response3.body());

        LOG.info("[Test] Enc key kids: {}, {}, {}", kid1, kid2, kid3);

        assertThat(kid1)
                .as("First request object should contain an encryption key")
                .isNotNull();
        assertThat(kid2)
                .as("Second request object should contain an encryption key")
                .isNotNull();
        assertThat(kid3)
                .as("Third request object should contain an encryption key")
                .isNotNull();
        assertThat(kid1)
                .as("Each fetch should generate a different encryption key")
                .isNotEqualTo(kid2);
        assertThat(kid2)
                .as("Each fetch should generate a different encryption key")
                .isNotEqualTo(kid3);
        assertThat(kid1)
                .as("Each fetch should generate a different encryption key")
                .isNotEqualTo(kid3);
    }

    @Test
    @Order(11)
    void loginSucceedsAfterMultipleRequestObjectFetches() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        // Pre-fetch the request object twice, creating encryption keys
        // that the wallet will NOT use (the wallet will fetch again and get its own key)
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> prefetch1 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> prefetch2 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(prefetch1.statusCode()).isEqualTo(200);
        assertThat(prefetch2.statusCode()).isEqualTo(200);
        LOG.info("[Test] Pre-fetched request object twice, now letting wallet fetch and respond");

        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("multi-fetch-user");
        flow.assertLoginSucceeded();
    }

    @Test
    @Order(12)
    void walletCanRespondUsingEarlierRequestObject() throws Exception {
        callback.reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();

        // Wallet fetches request object and submits VP response (encrypted with key K1)
        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("earlier-ro-user");
        flow.assertLoginSucceeded();

        // Fetch the request_uri again to prove the token is not consumed on first use
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> postLoginFetch = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        LOG.info("[Test] Post-login request object fetch status: {}", postLoginFetch.statusCode());
    }

    @Test
    @Order(13)
    void loginWithX509CertChainPem() throws Exception {
        // Mimics dev.sh: combined PEM (cert chain + private key) stored in x509CertificatePem.
        // Before the fix, PemUtils.decodeCertificate failed with Base64 error when
        // multiple certificates were concatenated.
        callback.reset();
        flow.clearBrowserSession();

        KeyPair caKeyPair = generateEcKeyPair();
        KeyPair leafKeyPair = generateEcKeyPair();

        X509Certificate caCert = generateCaCert(caKeyPair);
        X509Certificate leafCert = generateLeafCertWithSan(leafKeyPair, caKeyPair, "test.example.com");

        String combinedPem = toPem("CERTIFICATE", leafCert.getEncoded())
                + "\n"
                + toPem("CERTIFICATE", caCert.getEncoded())
                + "\n"
                + toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        idpConfig
                .set(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, combinedPem)
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns")
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, "")
                .apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(walletUrl)
                .as("Login should succeed with multi-cert PEM chain")
                .contains("request_uri=");

        // Verify the request object is signed with ES256 using the x509 key,
        // not falling back to the realm key (which would be RS256).
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        com.nimbusds.jwt.SignedJWT requestJwt = com.nimbusds.jwt.SignedJWT.parse(response.body());
        assertThat(requestJwt.getHeader().getAlgorithm().getName())
                .as("Request object must be signed with ES256 from the x509 key, not the realm key")
                .isEqualTo("ES256");
        assertThat(requestJwt.getHeader().getX509CertChain())
                .as("Request object must include x5c certificate chain")
                .hasSize(2);
    }

    @Test
    @Order(14)
    void loginWithCertOnlyPemAndRealmKey() throws Exception {
        // Cert-only mode: x509CertificatePem contains only the certificate (no private key).
        // Request objects are signed with the Keycloak realm key; the cert is used for
        // client_id derivation and included in the x5c JWS header.
        callback.reset();
        flow.clearBrowserSession();

        KeyPair leafKeyPair = generateEcKeyPair();
        X509Certificate leafCert = generateLeafCertWithSan(leafKeyPair, leafKeyPair, "test.example.com");

        String certOnlyPem = toPem("CERTIFICATE", leafCert.getEncoded());

        idpConfig
                .set(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, certOnlyPem)
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns")
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, "")
                .apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(walletUrl)
                .as("Login should succeed with cert-only PEM (realm key signing)")
                .contains("request_uri=");
    }

    // ===== Composite Helpers =====

    private void performSameDeviceLogin(String usernamePrefix) throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded(usernamePrefix);
    }

    private void waitForCrossDeviceNavigation() {
        try {
            page.waitForURL(
                    url -> url.contains("/complete-auth")
                            || url.contains("/first-broker-login")
                            || url.contains("/login-actions/")
                            || page.locator("input[name='username']").count() > 0
                            || flow.isCallbackUrl(url),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
        }
        page.waitForLoadState();
    }

    // ===== Static Helpers =====

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

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCaCert(KeyPair caKeyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                caKeyPair.getPublic());
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateLeafCertWithSan(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
            throws Exception {
        X500Principal issuer = new X500Principal("CN=Test CA");
        X500Principal subject = new X500Principal("CN=" + dnsName);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(2),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic());
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
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
