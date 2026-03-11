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
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.RegisterExtension;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractOid4vpE2eTest {

    @RegisterExtension
    final IdpConfigScope idpConfig = new IdpConfigScope(this::adminClient, Oid4vpE2eEnvironment.REALM);

    protected Oid4vpE2eEnvironment env;
    protected BrowserContext context;
    protected Page page;
    protected Oid4vpLoginFlowHelper flow;

    @BeforeAll
    void startEnvironment() throws Exception {
        env = Oid4vpE2eEnvironment.getOrStart();
    }

    @BeforeEach
    void createBrowserContext() {
        context = env.newBrowserContext();
        page = context.newPage();
        flow = env.newFlow(context, page, env.wallet());
    }

    @AfterEach
    void closeBrowserContext() {
        env.wallet().client().clearPreferredFormat();
        env.wallet().client().clearNextError();
        if (page != null) {
            page.close();
        }
        if (context != null) {
            context.close();
        }
    }

    protected KeycloakAdminClient adminClient() {
        return env.adminClient();
    }

    protected Oid4vpTestCallbackServer callback() {
        return env.callback();
    }

    protected Oid4vcContainer wallet() {
        return env.wallet();
    }

    protected Oid4vpLoginFlowHelper flowFor(Oid4vcContainer walletContainer) {
        return env.newFlow(context, page, walletContainer);
    }

    protected Oid4vcContainer newWallet(String alias) {
        return new Oid4vcContainer(env.walletImage())
                .withHostAccess()
                .withNetwork(env.network())
                .withNetworkAliases(alias)
                .withStatusList()
                .withStatusListBaseUrl("http://" + alias + ":8085");
    }

    protected void performSameDeviceLogin(String usernamePrefix) throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        PresentationResponse response = flow.submitToWallet(walletUrl);
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
            String completeAuthUrl = env.keycloakHostUrl() + "/realms/" + Oid4vpE2eEnvironment.REALM
                    + "/broker/oid4vp/endpoint/complete-auth?request_handle="
                    + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
            page.navigate(completeAuthUrl);
        }
        page.waitForLoadState();
    }

    protected void assertLoginFailed(PresentationResponse walletResponse, String... expectedSnippets) {
        String redirectUri = walletResponse.redirectUri();
        if (redirectUri != null) {
            page.navigate(redirectUri);
            page.waitForLoadState();
        }

        String bodyText = page.locator("body").textContent().toLowerCase();
        assertThat(flow.isCallbackUrl(page.url()))
                .as("Login should not succeed")
                .isFalse();
        assertThat(bodyText).as("Expected an error page").containsAnyOf(expectedSnippets);
    }

    protected void assertRevokedCredentialIsRejected(String formatLabel) throws Exception {
        assertRevokedCredentialIsRejected(formatLabel, null);
    }

    protected void assertRevokedCredentialIsRejected(String formatLabel, String credentialType) throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

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
                            "Revoked %s credential should be rejected. URL: %s, Body: %s",
                            formatLabel, page.url(), bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
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
                Map<String, Object> payload = env.objectMapper().readValue(payloadJson, Map.class);
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
                return java.net.URLDecoder.decode(param.substring(name.length() + 1), StandardCharsets.UTF_8);
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

    protected static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    protected static X509Certificate generateCaCert(KeyPair caKeyPair) throws Exception {
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

    protected static X509Certificate generateLeafCertWithSan(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
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

    protected static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }

    protected String encryptWalletResponse(ECKey publicKey, Map<String, Object> payload) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID())
                        .build(),
                new Payload(env.objectMapper().writeValueAsString(payload)));
        jwe.encrypt(new ECDHEncrypter(publicKey));
        return jwe.serialize();
    }

    protected static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
