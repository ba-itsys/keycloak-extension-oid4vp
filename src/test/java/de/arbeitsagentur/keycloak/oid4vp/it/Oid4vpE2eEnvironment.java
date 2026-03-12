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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import java.io.IOException;
import java.math.BigInteger;
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
import java.util.Comparator;
import java.util.Date;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * Shared integration-test environment. The browser and containers are expensive to start, so the
 * suite keeps one environment alive for the whole JVM and gives each test a fresh browser context.
 */
public final class Oid4vpE2eEnvironment implements AutoCloseable {

    public static final String REALM = "wallet-demo";

    private static final Logger LOG = LoggerFactory.getLogger(Oid4vpE2eEnvironment.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final DockerImageName WALLET_IMAGE =
            DockerImageName.parse("ghcr.io/dominikschlosser/oid4vc-dev:latest");
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

    private static Oid4vpE2eEnvironment instance;
    private static boolean shutdownHookRegistered;

    private final Network network;
    private final GenericContainer<?> keycloak;
    private final Oid4vcContainer wallet;
    private final Oid4vpTestCallbackServer callback;
    private final KeycloakAdminClient adminClient;
    private final Playwright playwright;
    private final Browser browser;
    private final String keycloakHostUrl;

    public static synchronized Oid4vpE2eEnvironment getOrStart() throws Exception {
        if (instance == null) {
            instance = new Oid4vpE2eEnvironment();
            if (!shutdownHookRegistered) {
                Runtime.getRuntime().addShutdownHook(new Thread(Oid4vpE2eEnvironment::closeQuietly));
                shutdownHookRegistered = true;
            }
        }
        return instance;
    }

    private Oid4vpE2eEnvironment() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        String callbackUrl = callback.localCallbackUrl();

        network = Network.newNetwork();
        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.4")
                .withNetwork(network)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm")
                .withLogConsumer(
                        frame -> LOG.info("[KC] {}", frame.getUtf8String().stripTrailing()))
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)));

        copyRealmImport(keycloak);
        copyProviderJars(keycloak);
        keycloak.start();
        keycloakHostUrl = "http://localhost:" + keycloak.getMappedPort(8080);

        wallet = new Oid4vcContainer(WALLET_IMAGE)
                .withHostAccess()
                .withNetwork(network)
                .withNetworkAliases("oid4vc-dev")
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-dev:8085");
        wallet.start();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
        adminClient = KeycloakAdminClient.login(OBJECT_MAPPER, keycloakHostUrl, "admin", "admin");

        String trustListUrl = "http://oid4vc-dev:8085/api/trustlist";
        KeyPair haipCaKeyPair = generateEcKeyPair();
        KeyPair haipLeafKeyPair = generateEcKeyPair();
        X509Certificate haipCaCert = generateCaCert(haipCaKeyPair);
        X509Certificate haipLeafCert = generateLeafCertWithSan(haipLeafKeyPair, haipCaKeyPair, "test.example.com");
        String haipCertPem = toPem("CERTIFICATE", haipLeafCert.getEncoded())
                + "\n"
                + toPem("CERTIFICATE", haipCaCert.getEncoded())
                + "\n"
                + toPem("PRIVATE KEY", haipLeafKeyPair.getPrivate().getEncoded());
        Oid4vpTestKeycloakSetup.configureOid4vpIdentityProvider(adminClient, REALM, trustListUrl, haipCertPem);
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, REALM, true);
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, REALM, "wallet-mock", callbackUrl);

        LOG.info("Setup complete. KC: {}, Wallet: {}", keycloakHostUrl, wallet.getBaseUrl());
    }

    BrowserContext newBrowserContext() {
        BrowserContext context = browser.newContext();
        context.addInitScript(SSE_INIT_SCRIPT);
        return context;
    }

    Oid4vpLoginFlowHelper newFlow(BrowserContext context, Page page, Oid4vcContainer walletContainer) {
        return new Oid4vpLoginFlowHelper(
                page, context, walletContainer, keycloakHostUrl, callback.localCallbackUrl(), REALM);
    }

    public Network network() {
        return network;
    }

    public GenericContainer<?> keycloak() {
        return keycloak;
    }

    public Oid4vcContainer wallet() {
        return wallet;
    }

    public Oid4vpTestCallbackServer callback() {
        return callback;
    }

    public KeycloakAdminClient adminClient() {
        return adminClient;
    }

    public ObjectMapper objectMapper() {
        return OBJECT_MAPPER;
    }

    public String keycloakHostUrl() {
        return keycloakHostUrl;
    }

    public String callbackUrl() {
        return callback.localCallbackUrl();
    }

    public DockerImageName walletImage() {
        return WALLET_IMAGE;
    }

    @Override
    public void close() {
        if (browser != null) {
            browser.close();
        }
        if (playwright != null) {
            playwright.close();
        }
        if (keycloak != null) {
            keycloak.stop();
        }
        if (wallet != null) {
            wallet.stop();
        }
        if (network != null) {
            network.close();
        }
        if (callback != null) {
            callback.close();
        }
    }

    private static synchronized void closeQuietly() {
        if (instance == null) {
            return;
        }
        try {
            instance.close();
        } catch (Exception e) {
            LOG.warn("Failed to close shared OID4VP test environment", e);
        } finally {
            instance = null;
        }
    }

    private static void copyRealmImport(GenericContainer<?> keycloak) {
        Path realmExport = Path.of("src/test/resources/realm-export.json").toAbsolutePath();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport), "/opt/keycloak/data/import/realm-export.json");
    }

    private static void copyProviderJars(GenericContainer<?> keycloak) throws IOException {
        Path providerJar = findProviderJar();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(providerJar), "/opt/keycloak/providers/" + providerJar.getFileName());

        Path deps = Path.of("target/providers").toAbsolutePath();
        if (!Files.isDirectory(deps)) {
            return;
        }
        try (Stream<Path> stream = Files.list(deps)) {
            for (Path jar : stream.filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().startsWith("keycloak-extension-oid4vp-"))
                    .toList()) {
                keycloak.withCopyFileToContainer(
                        MountableFile.forHostPath(jar), "/opt/keycloak/providers/" + jar.getFileName());
            }
        }
    }

    private static Path findProviderJar() throws IOException {
        Path target = Path.of("target").toAbsolutePath();
        try (Stream<Path> stream = Files.list(target)) {
            return stream.filter(path -> path.getFileName().toString().startsWith("keycloak-extension-oid4vp-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                    .max(Comparator.comparingLong(path -> path.toFile().lastModified()))
                    .orElseThrow(() -> new IllegalStateException("Provider jar not found in target/"));
        }
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
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
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateLeafCertWithSan(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
            throws Exception {
        X500Principal issuer = new X500Principal("CN=Test CA");
        X500Principal subject = new X500Principal("CN=Test Verifier");
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
}
