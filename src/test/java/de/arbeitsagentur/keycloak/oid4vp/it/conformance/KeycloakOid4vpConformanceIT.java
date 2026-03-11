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
package de.arbeitsagentur.keycloak.oid4vp.it.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpE2eEnvironment;
import de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup;
import de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.IdpMapperConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.Oid4vpIdentityProviderSpec;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.PemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Runs the OIDF OID4VP verifier module against the Keycloak verifier for the supported
 * client-id-scheme / credential-format combinations.
 */
@EnabledIf("isConformanceEnabled")
class KeycloakOid4vpConformanceIT {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpConformanceIT.class);
    private static final Duration MAX_WAIT = Duration.ofMinutes(15);
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(2);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String OIDF_MDL_ISSUER_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIICqTCCAlCgAwIBAgIUEmctHgzxSGqk6Z8Eb+0s97VZdpowCgYIKoZIzj0EAwIw
            gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
            BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
            BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjUw
            NzMwMDc0NzIyWhcNMjYwNzMwMDc0NzIyWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
            BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
            DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
            ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
            lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
            48WXI8xhIphoNN7AejajgZcwgZQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
            Af8EBAMCAQYwIQYDVR0SBBowGIEWY2VydGlmaWNhdGlvbkBvaWRmLm9yZzAsBgNV
            HR8EJTAjMCGgH6AdhhtodHRwOi8vZXhhbXBsZS5jb20vbXljYS5jcmwwHQYDVR0O
            BBYEFHhk9LVVH8Gt9ZgfxgyhSl921XOhMAoGCCqGSM49BAMCA0cAMEQCICBxjCq9
            efAwMKREK+k0OXBtiQCbFD7QdpyH42LVYfdvAiAurlZwp9PtmQZzoSYDUvXpZM5v
            TvFLVc4ESGy3AtdC+g==
            -----END CERTIFICATE-----
            """;

    private static OidfConformanceSettings settings;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(KeycloakOid4vpConformanceIT.class.getClassLoader());
    }

    private static Oid4vpE2eEnvironment environment;
    private static OidfConformanceClient conformanceClient;
    private static PublicBaseUrlExposure publicExposure;
    private static X509Certificate oidfMdlIssuerCertificate;

    static boolean isConformanceEnabled() {
        OidfConformanceSettings loaded = OidfConformanceSettings.load();
        if (!loaded.runInCi() && "true".equalsIgnoreCase(System.getenv("CI"))) {
            return false;
        }
        if (!loaded.hasApiKey()) {
            return false;
        }
        return loaded.publicBaseUrl() != null || NgrokTunnel.isAvailable();
    }

    @BeforeAll
    static void setUp() throws Exception {
        settings = OidfConformanceSettings.load();
        Assumptions.assumeTrue(settings.hasApiKey(), "Set OIDF_CONFORMANCE_API_KEY to run the conformance IT");
        environment = Oid4vpE2eEnvironment.getOrStart();
        publicExposure =
                PublicBaseUrlExposure.open(settings, environment.keycloak().getMappedPort(8080));
        conformanceClient = new OidfConformanceClient(
                HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .connectTimeout(Duration.ofSeconds(30))
                        .build(),
                OBJECT_MAPPER,
                settings.suiteBaseUrl(),
                settings.apiKey());
        oidfMdlIssuerCertificate = parseCertificatePem(OIDF_MDL_ISSUER_CERTIFICATE);
    }

    @AfterAll
    static void tearDown() {
        if (publicExposure != null) {
            publicExposure.close();
        }
    }

    static Stream<ConformanceScenario> scenarios() {
        return Stream.of(
                ConformanceScenario.sdJwtX509SanDns(),
                ConformanceScenario.sdJwtX509Hash(),
                ConformanceScenario.isoMdlX509SanDns(),
                ConformanceScenario.isoMdlX509Hash());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    @Timeout(value = 25, unit = TimeUnit.MINUTES)
    void verifierPassesOidfModuleForScenario(ConformanceScenario scenario) throws Exception {
        String publicBaseUrl = publicExposure.publicBaseUrl();
        String publicHost = URI.create(publicBaseUrl).getHost();
        SigningMaterial signingMaterial = SigningMaterial.generate(publicHost);
        String trustListJwt = buildTrustListJwt(signingMaterial.ecKey(), scenario.trustedCertificates(signingMaterial));

        try (TrustListContainer trustList = TrustListContainer.start(environment.network(), trustListJwt)) {
            String identityProviderAlias = configureKeycloakForConformance(
                    signingMaterial, scenario, trustList.trustListUrl().toString());

            String planId = null;
            boolean deletePlan = !settings.keepPlansOnSuccess();
            try {
                OidfConformanceClient.ConformancePlan plan = conformanceClient.createPlan(
                        settings.planName(),
                        scenario.variant(),
                        buildPlanConfig(signingMaterial, publicHost, scenario));
                assertLocalAuthorizationRequestMatchesScenario(
                        publicBaseUrl, publicHost, identityProviderAlias, signingMaterial, scenario);
                planId = plan.id();
                String moduleName = resolveModuleName(plan);
                OidfConformanceClient.ConformanceRunStart run = conformanceClient.startModule(plan.id(), moduleName);

                awaitWaitingState(run.runId());
                URI authorizationEndpoint = resolveAuthorizationEndpoint(run.runId(), run.runUrl());
                triggerSameDeviceFlow(publicBaseUrl, identityProviderAlias, authorizationEndpoint);

                OidfConformanceClient.ConformanceRunInfo result = awaitRunCompletion(run.runId());
                assertThat(isPassed(result.status(), result.result()))
                        .as(
                                "%s should finish successfully. status=%s result=%s log=%s",
                                scenario,
                                result.status(),
                                result.result(),
                                String.join("\n", conformanceClient.loadRunLog(run.runId())))
                        .isTrue();
            } catch (Throwable t) {
                deletePlan = false;
                throw t;
            } finally {
                Oid4vpTestKeycloakSetup.deleteIdentityProviderIfExists(
                        environment.adminClient(), Oid4vpE2eEnvironment.REALM, identityProviderAlias);
                if (deletePlan && planId != null) {
                    conformanceClient.deletePlan(planId);
                } else if (planId != null) {
                    LOG.info("Keeping OIDF conformance plan {} for inspection", planId);
                }
            }
        }
    }

    private static String configureKeycloakForConformance(
            SigningMaterial signingMaterial, ConformanceScenario scenario, String trustListUrl) throws Exception {
        String alias = "oid4vp-conf-" + UUID.randomUUID().toString().replace("-", "");
        Oid4vpTestKeycloakSetup.replaceOid4vpIdentityProvider(
                environment.adminClient(),
                Oid4vpE2eEnvironment.REALM,
                new Oid4vpIdentityProviderSpec(
                        alias,
                        signingMaterial.combinedPem(),
                        scenario.variant().clientIdScheme().configValue(),
                        scenario.variant().responseMode().parameterValue(),
                        scenario.enforceHaip(),
                        null,
                        scenario.credentialProfile().userMappingClaim(),
                        scenario.credentialProfile().userMappingClaimMdoc(),
                        trustListUrl,
                        scenario.credentialProfile().mappers()));
        return alias;
    }

    private static Map<String, Object> buildPlanConfig(
            SigningMaterial signingMaterial, String publicHost, ConformanceScenario scenario) throws Exception {
        Map<String, Object> signingJwk =
                new LinkedHashMap<>(signingMaterial.ecKey().toJSONObject());
        signingJwk.put(
                "x5c",
                List.of(Base64.getEncoder()
                        .encodeToString(signingMaterial.certificate().getEncoded())));
        return Map.of(
                "alias",
                "keycloak-oid4vp-" + UUID.randomUUID(),
                "description",
                "Keycloak verifier conformance test: " + scenario,
                "publish",
                "private",
                "client",
                Map.of("client_id", scenario.planClientId(signingMaterial, publicHost)),
                "credential",
                Map.of("signing_jwk", signingJwk));
    }

    private static String resolveModuleName(OidfConformanceClient.ConformancePlan plan) {
        if (settings.requestedModule() != null && !settings.requestedModule().isBlank()) {
            return settings.requestedModule();
        }
        return plan.modules().stream()
                .findFirst()
                .map(OidfConformanceClient.ConformanceModule::name)
                .orElseThrow(() -> new IllegalStateException("Conformance plan did not return any test modules"));
    }

    private static URI resolveAuthorizationEndpoint(String runId, URI runnerUrl) throws Exception {
        OidfConformanceClient.ConformanceRunInfo info = conformanceClient.loadRunInfo(runId);
        if (info.authorizationEndpoint() != null) {
            return info.authorizationEndpoint();
        }
        if (runnerUrl != null && runnerUrl.toString().contains("/authorize")) {
            return runnerUrl;
        }
        if (runnerUrl != null) {
            return URI.create(runnerUrl.toString().replaceAll("/$", "") + "/authorize");
        }
        throw new IllegalStateException("OIDF run info did not expose authorization_endpoint");
    }

    private static void triggerSameDeviceFlow(
            String publicBaseUrl, String identityProviderAlias, URI authorizationEndpoint) throws Exception {
        SameDeviceAuthorizationRequest localRequest =
                fetchSameDeviceAuthorizationRequest(publicBaseUrl, identityProviderAlias);
        URI suiteAuthorizationRequest = new Oid4vpAuthorizationRequestParameters(
                        localRequest.clientId(), localRequest.requestUri())
                .toAuthorizationEndpoint(authorizationEndpoint);

        HttpResponse<String> walletResponse = localRequest
                .browserSession()
                .send(
                        HttpRequest.newBuilder(suiteAuthorizationRequest)
                                .header("Accept", "text/html,application/json")
                                .header("ngrok-skip-browser-warning", "true")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(walletResponse.statusCode())
                .as(
                        "Unexpected suite authorization response for %s body=%s",
                        suiteAuthorizationRequest, walletResponse.body())
                .isBetween(200, 399);
    }

    private static void assertLocalAuthorizationRequestMatchesScenario(
            String publicBaseUrl,
            String publicHost,
            String identityProviderAlias,
            SigningMaterial signingMaterial,
            ConformanceScenario scenario)
            throws Exception {
        SameDeviceAuthorizationRequest localRequest =
                fetchSameDeviceAuthorizationRequest(publicBaseUrl, identityProviderAlias);
        String expectedClientId =
                scenario.variant().clientIdScheme().formatValue(scenario.planClientId(signingMaterial, publicHost));
        assertThat(localRequest.clientId())
                .as("Unexpected wallet URL client_id for %s request=%s", scenario, localRequest.claims())
                .isEqualTo(expectedClientId);
        assertThat(localRequest.claims().get("client_id"))
                .as("Unexpected request object client_id for %s request=%s", scenario, localRequest.claims())
                .isEqualTo(expectedClientId);

        Object dcqlObject = localRequest.claims().get("dcql_query");
        assertThat(dcqlObject)
                .as("Missing dcql_query in request object for %s request=%s", scenario, localRequest.claims())
                .isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        List<Object> credentials = (List<Object>) ((Map<String, Object>) dcqlObject).get("credentials");
        assertThat(credentials)
                .as("Unexpected dcql_query in request object for %s request=%s", scenario, localRequest.claims())
                .hasSize(1);
    }

    private static SameDeviceAuthorizationRequest fetchSameDeviceAuthorizationRequest(
            String publicBaseUrl, String identityProviderAlias) throws Exception {
        CookieManager cookies = new CookieManager();
        HttpClient browserSession = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build();

        String codeVerifier = UUID.randomUUID() + UUID.randomUUID().toString();
        byte[] challengeHash =
                MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeHash);
        String loginUrl = publicBaseUrl + "/realms/" + Oid4vpE2eEnvironment.REALM + "/protocol/openid-connect/auth"
                + "?client_id=wallet-mock"
                + "&response_type=code"
                + "&scope=openid"
                + "&redirect_uri=" + URLEncoder.encode(publicBaseUrl + "/callback", StandardCharsets.UTF_8)
                + "&code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)
                + "&code_challenge_method=S256"
                + "&kc_idp_hint=" + URLEncoder.encode(identityProviderAlias, StandardCharsets.UTF_8);

        HttpResponse<String> loginPage = browserSession.send(
                HttpRequest.newBuilder(URI.create(loginUrl))
                        .header("Accept", "text/html")
                        .header("ngrok-skip-browser-warning", "true")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(loginPage.statusCode()).isBetween(200, 399);

        String walletUrl = extractSameDeviceWalletUrl(loginPage.body());
        Oid4vpAuthorizationRequestParameters params = Oid4vpAuthorizationRequestParameters.parse(walletUrl);
        HttpResponse<String> requestObjectResponse = browserSession.send(
                HttpRequest.newBuilder(params.requestUri())
                        .header("Accept", "application/oauth-authz-req+jwt,application/jwt,text/plain")
                        .header("ngrok-skip-browser-warning", "true")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(requestObjectResponse.statusCode())
                .as(
                        "Unexpected request object response for %s body=%s",
                        params.requestUri(), requestObjectResponse.body())
                .isEqualTo(200);

        SignedJWT requestObject = SignedJWT.parse(requestObjectResponse.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = OBJECT_MAPPER.readValue(
                OBJECT_MAPPER.writeValueAsBytes(requestObject.getJWTClaimsSet().getClaims()), Map.class);
        return new SameDeviceAuthorizationRequest(browserSession, params.clientId(), params.requestUri(), claims);
    }

    private static String extractSameDeviceWalletUrl(String loginHtml) {
        int marker = loginHtml.indexOf("Open Wallet App");
        if (marker < 0) {
            throw new IllegalStateException("OID4VP login page did not contain the same-device action");
        }
        int hrefMarker = loginHtml.lastIndexOf("href=\"", marker);
        if (hrefMarker < 0) {
            throw new IllegalStateException("OID4VP login page did not contain a wallet href");
        }
        int valueStart = hrefMarker + 6;
        int valueEnd = loginHtml.indexOf('"', valueStart);
        if (valueEnd < 0) {
            throw new IllegalStateException("OID4VP login page contained an unterminated wallet href");
        }
        return loginHtml.substring(valueStart, valueEnd).replace("&amp;", "&");
    }

    private record SameDeviceAuthorizationRequest(
            HttpClient browserSession, String clientId, URI requestUri, Map<String, Object> claims) {}

    private static void awaitWaitingState(String runId) throws Exception {
        Instant deadline = Instant.now().plus(Duration.ofMinutes(1));
        String lastStatus = null;
        while (Instant.now().isBefore(deadline)) {
            OidfConformanceClient.ConformanceRunInfo info = conformanceClient.loadRunInfo(runId);
            lastStatus = info.status();
            if ("WAITING".equalsIgnoreCase(lastStatus)) {
                return;
            }
            if (isTerminal(lastStatus)) {
                throw new AssertionError("Conformance run entered terminal state before verifier call: " + lastStatus);
            }
            Thread.sleep(250);
        }
        throw new AssertionError("Conformance run did not reach WAITING in time. lastStatus=" + lastStatus);
    }

    private static OidfConformanceClient.ConformanceRunInfo awaitRunCompletion(String runId) throws Exception {
        Instant deadline = Instant.now().plus(MAX_WAIT);
        OidfConformanceClient.ConformanceRunInfo lastInfo = null;
        while (Instant.now().isBefore(deadline)) {
            lastInfo = conformanceClient.loadRunInfo(runId);
            if (isTerminal(lastInfo.status())) {
                return lastInfo;
            }
            Thread.sleep(POLL_INTERVAL.toMillis());
        }
        throw new AssertionError("Conformance run did not finish in time. lastStatus="
                + (lastInfo != null ? lastInfo.status() : "unknown"));
    }

    private static boolean isTerminal(String status) {
        if (status == null) {
            return false;
        }
        String normalized = status.trim().toUpperCase();
        return normalized.equals("FINISHED") || normalized.equals("INTERRUPTED");
    }

    private static boolean isPassed(String status, String result) {
        if (status == null || result == null) {
            return false;
        }
        return "FINISHED".equalsIgnoreCase(status)
                && ("PASSED".equalsIgnoreCase(result)
                        || "SUCCESS".equalsIgnoreCase(result)
                        || "WARNING".equalsIgnoreCase(result));
    }

    private static String buildTrustListJwt(ECKey signingKey, List<X509Certificate> trustedCertificates)
            throws Exception {
        List<Map<String, Object>> certificateEntries = new ArrayList<>();
        for (X509Certificate certificate : trustedCertificates) {
            certificateEntries.add(Map.of("val", Base64.getEncoder().encodeToString(certificate.getEncoded())));
        }
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim(
                        "TrustedEntitiesList",
                        List.of(Map.of(
                                "TrustedEntityServices",
                                List.of(Map.of(
                                        "ServiceInformation",
                                        Map.of(
                                                "ServiceDigitalIdentity",
                                                Map.of("X509Certificates", certificateEntries)))))))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claims);
        JWSSigner signer = new ECDSASigner(signingKey.toECPrivateKey());
        jwt.sign(signer);
        return jwt.serialize();
    }

    private static String computeX509Hash(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static X509Certificate parseCertificatePem(String pem) throws Exception {
        return PemUtils.decodeCertificate(pem);
    }

    private record SigningMaterial(ECKey ecKey, X509Certificate certificate, String combinedPem) {

        static SigningMaterial generate(String publicHost) throws Exception {
            ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            KeyPair issuerKeyPair = new ECKeyGenerator(Curve.P_256).generate().toKeyPair();
            X509Certificate issuerCertificate = selfSignedCertificate(issuerKeyPair, "Conformance Test CA");
            X509Certificate certificate =
                    issuedCertificate(ecKey.toKeyPair(), issuerKeyPair, issuerCertificate, publicHost);
            String combinedPem = toPem("CERTIFICATE", certificate.getEncoded())
                    + "\n"
                    + toPem("CERTIFICATE", issuerCertificate.getEncoded())
                    + "\n"
                    + toPem("PRIVATE KEY", ecKey.toECPrivateKey().getEncoded());
            return new SigningMaterial(ecKey, certificate, combinedPem);
        }

        private static X509Certificate selfSignedCertificate(KeyPair keyPair, String commonName) throws Exception {
            X500Principal subject = new X500Principal("CN=" + commonName);
            Instant notBefore = Instant.now().minus(1, ChronoUnit.MINUTES);
            Instant notAfter = Instant.now().plus(1, ChronoUnit.DAYS);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    new BigInteger(128, new SecureRandom()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    subject,
                    keyPair.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, commonName)));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().getCertificate(holder);
        }

        private static X509Certificate issuedCertificate(
                KeyPair subjectKeyPair, KeyPair issuerKeyPair, X509Certificate issuerCertificate, String hostname)
                throws Exception {
            X500Principal subject = new X500Principal("CN=" + hostname);
            Instant notBefore = Instant.now().minus(1, ChronoUnit.MINUTES);
            Instant notAfter = Instant.now().plus(1, ChronoUnit.DAYS);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuerCertificate.getSubjectX500Principal(),
                    new BigInteger(128, new SecureRandom()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    subject,
                    subjectKeyPair.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(
                    Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().getCertificate(holder);
        }
    }

    private record PublicBaseUrlExposure(String publicBaseUrl, AutoCloseable delegate) implements AutoCloseable {

        static PublicBaseUrlExposure open(OidfConformanceSettings settings, int localPort) throws Exception {
            if (settings.publicBaseUrl() != null && !settings.publicBaseUrl().isBlank()) {
                return new PublicBaseUrlExposure(settings.publicBaseUrl(), () -> {});
            }
            NgrokTunnel tunnel = NgrokTunnel.start(localPort, Duration.ofSeconds(30));
            return new PublicBaseUrlExposure(tunnel.publicUrl(), tunnel);
        }

        @Override
        public void close() {
            try {
                delegate.close();
            } catch (Exception e) {
                LOG.warn("Failed to close public URL exposure", e);
            }
        }
    }

    private record TrustListContainer(GenericContainer<?> container, URI trustListUrl) implements AutoCloseable {

        static TrustListContainer start(Network network, String trustListJwt) throws IOException {
            Path trustListDir = Files.createTempDirectory("oid4vp-conformance-trustlist-");
            Files.writeString(trustListDir.resolve("trustlist.jwt"), trustListJwt, StandardCharsets.UTF_8);
            String alias = "oidf-trustlist-" + UUID.randomUUID().toString().replace("-", "");
            GenericContainer<?> container = new GenericContainer<>("python:3.12-alpine")
                    .withNetwork(network)
                    .withNetworkAliases(alias)
                    .withCopyFileToContainer(MountableFile.forHostPath(trustListDir), "/srv/trustlist")
                    .withCommand("python", "-m", "http.server", "8080", "--directory", "/srv/trustlist")
                    .waitingFor(Wait.forListeningPort());
            container.start();
            return new TrustListContainer(container, URI.create("http://" + alias + ":8080/trustlist.jwt"));
        }

        @Override
        public void close() {
            if (container != null) {
                container.stop();
            }
        }
    }

    private record NgrokTunnel(Process process, Path logFile, String publicUrl) implements AutoCloseable {

        static boolean isAvailable() {
            String path = System.getenv("PATH");
            if (path == null || path.isBlank()) {
                return false;
            }
            for (String entry : path.split(File.pathSeparator)) {
                Path candidate = Path.of(entry).resolve("ngrok");
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return true;
                }
            }
            return false;
        }

        static NgrokTunnel start(int localPort, Duration timeout) throws Exception {
            Path logFile = Files.createTempFile("oid4vp-ngrok-", ".log");
            Process process = new ProcessBuilder(
                            "ngrok", "http", String.valueOf(localPort), "--log=stdout", "--log-format=json")
                    .redirectErrorStream(true)
                    .redirectOutput(logFile.toFile())
                    .start();
            Instant deadline = Instant.now().plus(timeout);
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(2))
                    .build();
            while (Instant.now().isBefore(deadline)) {
                if (!process.isAlive()) {
                    throw new IllegalStateException("ngrok exited early: " + readLogSummary(logFile));
                }
                try {
                    String publicUrl = findNgrokPublicUrl(client, localPort);
                    if (publicUrl != null && !publicUrl.isBlank()) {
                        return new NgrokTunnel(process, logFile, publicUrl);
                    }
                } catch (Exception ignored) {
                }
                Thread.sleep(250);
            }
            throw new IllegalStateException("Timed out waiting for ngrok tunnel. Log: " + logFile);
        }

        @Override
        public void close() {
            if (process != null) {
                process.destroy();
            }
        }

        private static String findNgrokPublicUrl(HttpClient client, int localPort) throws Exception {
            for (int apiPort = 4040; apiPort <= 4045; apiPort++) {
                try {
                    HttpResponse<String> response = client.send(
                            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + apiPort + "/api/tunnels"))
                                    .GET()
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
                    String publicUrl = findNgrokPublicUrl(response.body(), localPort);
                    if (publicUrl != null && !publicUrl.isBlank()) {
                        return publicUrl;
                    }
                } catch (Exception ignored) {
                }
            }
            return null;
        }

        private static String findNgrokPublicUrl(String responseBody, int localPort) throws Exception {
            String expectedSuffix = ":" + localPort;
            for (var tunnel : OBJECT_MAPPER.readTree(responseBody).path("tunnels")) {
                String addr = tunnel.path("config").path("addr").asText("");
                if (addr.endsWith(expectedSuffix) || addr.contains("localhost" + expectedSuffix)) {
                    return tunnel.path("public_url").asText(null);
                }
            }
            return null;
        }

        private static String readLogSummary(Path logFile) {
            try {
                String log = Files.readString(logFile, StandardCharsets.UTF_8).trim();
                return log.isBlank() ? "log file empty: " + logFile : log;
            } catch (IOException e) {
                return "could not read log file " + logFile + ": " + e.getMessage();
            }
        }
    }

    private record ConformanceScenario(
            String name, OidfConformanceVariant variant, CredentialProfile credentialProfile, boolean enforceHaip) {

        static ConformanceScenario sdJwtX509SanDns() {
            return new ConformanceScenario(
                    "sd_jwt_vc x509_san_dns direct_post.jwt",
                    new OidfConformanceVariant(
                            OidfConformanceVariant.OidfConformanceCredentialFormat.SD_JWT_VC,
                            Oid4vpClientIdScheme.X509_SAN_DNS,
                            OidfConformanceVariant.OidfConformanceRequestMethod.REQUEST_URI_SIGNED,
                            Oid4vpResponseMode.DIRECT_POST_JWT),
                    CredentialProfile.SD_JWT_VC,
                    false);
        }

        static ConformanceScenario sdJwtX509Hash() {
            return new ConformanceScenario(
                    "sd_jwt_vc x509_hash direct_post.jwt",
                    new OidfConformanceVariant(
                            OidfConformanceVariant.OidfConformanceCredentialFormat.SD_JWT_VC,
                            Oid4vpClientIdScheme.X509_HASH,
                            OidfConformanceVariant.OidfConformanceRequestMethod.REQUEST_URI_SIGNED,
                            Oid4vpResponseMode.DIRECT_POST_JWT),
                    CredentialProfile.SD_JWT_VC,
                    true);
        }

        static ConformanceScenario isoMdlX509SanDns() {
            return new ConformanceScenario(
                    "iso_mdl x509_san_dns direct_post.jwt",
                    new OidfConformanceVariant(
                            OidfConformanceVariant.OidfConformanceCredentialFormat.ISO_MDL,
                            Oid4vpClientIdScheme.X509_SAN_DNS,
                            OidfConformanceVariant.OidfConformanceRequestMethod.REQUEST_URI_SIGNED,
                            Oid4vpResponseMode.DIRECT_POST_JWT),
                    CredentialProfile.ISO_MDL,
                    false);
        }

        static ConformanceScenario isoMdlX509Hash() {
            return new ConformanceScenario(
                    "iso_mdl x509_hash direct_post.jwt",
                    new OidfConformanceVariant(
                            OidfConformanceVariant.OidfConformanceCredentialFormat.ISO_MDL,
                            Oid4vpClientIdScheme.X509_HASH,
                            OidfConformanceVariant.OidfConformanceRequestMethod.REQUEST_URI_SIGNED,
                            Oid4vpResponseMode.DIRECT_POST_JWT),
                    CredentialProfile.ISO_MDL,
                    true);
        }

        String planClientId(SigningMaterial signingMaterial, String publicHost) throws Exception {
            return switch (variant.clientIdScheme()) {
                case X509_SAN_DNS -> publicHost;
                case X509_HASH -> computeX509Hash(signingMaterial.certificate());
                case PLAIN ->
                    throw new IllegalStateException("OIDF verifier conformance does not use plain client IDs");
            };
        }

        List<X509Certificate> trustedCertificates(SigningMaterial signingMaterial) {
            return credentialProfile.trustedCertificates(signingMaterial.certificate());
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private enum CredentialProfile {
        SD_JWT_VC(
                "given_name",
                "given_name",
                List.of(
                        mapper("sd-jwt-given_name", "dc+sd-jwt", "pid", "given_name", "firstName"),
                        mapper("sd-jwt-family_name", "dc+sd-jwt", "pid", "family_name", "lastName"))) {
            @Override
            List<X509Certificate> trustedCertificates(X509Certificate signingCertificate) {
                return List.of(signingCertificate);
            }
        },
        ISO_MDL(
                "given_name",
                "org.iso.18013.5.1/given_name",
                List.of(
                        mapper(
                                "mdoc-given_name",
                                "mso_mdoc",
                                "org.iso.18013.5.1.mDL",
                                "org.iso.18013.5.1/given_name",
                                "firstName"),
                        mapper(
                                "mdoc-family_name",
                                "mso_mdoc",
                                "org.iso.18013.5.1.mDL",
                                "org.iso.18013.5.1/family_name",
                                "lastName"))) {
            @Override
            List<X509Certificate> trustedCertificates(X509Certificate signingCertificate) {
                return List.of(signingCertificate, oidfMdlIssuerCertificate);
            }
        };

        private final String userMappingClaim;
        private final String userMappingClaimMdoc;
        private final List<IdpMapperConfig> mappers;

        CredentialProfile(String userMappingClaim, String userMappingClaimMdoc, List<IdpMapperConfig> mappers) {
            this.userMappingClaim = userMappingClaim;
            this.userMappingClaimMdoc = userMappingClaimMdoc;
            this.mappers = mappers;
        }

        abstract List<X509Certificate> trustedCertificates(X509Certificate signingCertificate);

        String userMappingClaim() {
            return userMappingClaim;
        }

        String userMappingClaimMdoc() {
            return userMappingClaimMdoc;
        }

        List<IdpMapperConfig> mappers() {
            return mappers;
        }

        private static IdpMapperConfig mapper(
                String name, String format, String credentialType, String claim, String userAttribute) {
            Map<String, String> config = new LinkedHashMap<>();
            config.put("syncMode", "INHERIT");
            config.put("credential.format", format);
            config.put("credential.type", credentialType);
            config.put("claim", claim);
            config.put("user.attribute", userAttribute);
            return new IdpMapperConfig(name, "oid4vp-user-attribute-mapper", config);
        }
    }

    private static String toPem(String type, byte[] der) {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + encoded + "\n-----END " + type + "-----";
    }
}
