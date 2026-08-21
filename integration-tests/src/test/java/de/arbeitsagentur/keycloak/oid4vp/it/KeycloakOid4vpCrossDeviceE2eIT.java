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

import com.microsoft.playwright.Page;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpCrossDeviceE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakOid4vpCrossDeviceE2eIT.class);

    @Test
    void crossDeviceFirstLogin() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        LOG.info("[Test] Cross-device wallet URL: {}", walletUrl);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        LOG.info("[Test] Cross-device wallet response: {}", walletResponse.rawBody());

        assertThat(walletResponse.redirectUri()).isNull();
        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceSecondLogin() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-repeat-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceMdocPresentationFlow() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        replaceDcqlMappers(Oid4vpTestKeycloakSetup.mdocPidMappers());
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        LOG.info("[Test] Cross-device mDoc wallet URL: {}", walletUrl);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-mdoc-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void sameDevicePrefetchDoesNotInvalidateCrossDeviceFlow() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String sameDeviceWalletUrl = flow.getSameDeviceWalletUrl();
        String crossDeviceWalletUrl = flow.getCrossDeviceWalletUrl();
        String sameDeviceRequestUri = Oid4vpLoginFlowHelper.extractRequestUri(sameDeviceWalletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> prefetch1 = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(sameDeviceRequestUri))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> prefetch2 = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(sameDeviceRequestUri))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(prefetch1.statusCode()).isEqualTo(200);
        assertThat(prefetch2.statusCode()).isEqualTo(200);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(crossDeviceWalletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-after-same-prefetch");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceCompletionCanBeObservedBySecondSseClientWithSameBrowserSession() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String state = flow.getState();

        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();
        String sseStatusUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/cross-device/status?state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8);
        String cookieHeader = browserCookieHeader(sseStatusUrl);
        HttpResponse<String> sseResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(sseStatusUrl))
                                .header("Cookie", cookieHeader)
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(sseResponse.statusCode()).isEqualTo(200);
        assertThat(sseResponse.body()).contains("event:complete");
        String redirectUri = extractRedirectUriFromSseResponse(sseResponse.body());
        assertThat(redirectUri).contains("complete-auth");

        page.navigate(redirectUri);
        flow.completeFirstBrokerLoginIfNeeded("cross-device-second-sse-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceStatusWithoutBrowserSessionCookieReturnsNoContent() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String state = flow.getState();

        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        String sseStatusUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/cross-device/status?state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8);
        HttpResponse<String> sseResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(sseStatusUrl))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(sseResponse.statusCode()).isEqualTo(204);
    }

    @Test
    void crossDeviceCompleteAuthWithoutBrowserSessionCookieIsRejected() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String state = flow.getState();

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        // A foreign party can only observe the public state (in the request_uri / SSE URL), not the
        // single-use response_code generated during direct_post. Without it, /complete-auth is
        // rejected at the response_code gate before any browser-session check, so the foreign browser
        // never completes the login.
        String completeAuthUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/complete-auth?state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8);

        var otherContext = newBrowserContext();
        var otherPage = otherContext.newPage();
        try {
            otherPage.navigate(completeAuthUrl);
            otherPage.waitForLoadState();
            // The browser opened this URL, so the rejection is rendered as Keycloak's error page.
            String body = otherPage.locator("body").textContent().toLowerCase();
            assertThat(body).contains("this login link is not valid");
            assertThat(flow.isCallbackUrl(otherPage.url()))
                    .as("Foreign browser must not complete the login")
                    .isFalse();
        } finally {
            otherPage.close();
            otherContext.close();
        }
    }

    /**
     * A declined presentation must move the browser in the cross-device flow too. The wallet runs on
     * another device, so the {@code redirect_uri} the response URI returns reaches only the wallet's
     * own user agent; the browser learns of the decline through the SSE stream instead. Without that
     * signal it keeps polling for a completion that never comes and shows a generic timeout only
     * after the stream's full lifetime.
     */
    @Test
    void crossDeviceWalletErrorReturnsBrowserToLoginPage() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));
        wallet().client().setNextError("access_denied", "User denied consent");

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getCrossDeviceWalletUrl();

            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
            assertThat(Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody()))
                    .isEqualTo("{}");
            assertLoginFailedBecauseOf("denied consent");

            // Arriving well inside the stream's lifetime is the point: a timeout would also move the
            // browser eventually, but only after the End-User has waited the stream out.
            page.waitForURL(
                    url -> url.contains("/failed")
                            || page.locator("a#social-oid4vp").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
            page.waitForLoadState();
        } finally {
            wallet().client().clearNextError();
        }

        assertThat(flow.isCallbackUrl(page.url()))
                .as("A declined presentation must not complete the login")
                .isFalse();
        page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
    }

    /**
     * The stream itself must carry the decline. Reading it directly pins the contract the browser
     * script depends on: a {@code failed} event whose payload holds the failure URL, rather than
     * the stream falling silent until it times out.
     */
    @Test
    void crossDeviceSseEmitsFailedEventWithFailureUrl() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String state = flow.getState();

        page.navigate("about:blank");

        wallet().client().setNextError("access_denied", "User denied consent");
        try {
            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
            assertThat(Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody()))
                    .isEqualTo("{}");
            assertLoginFailedBecauseOf("denied consent");
        } finally {
            wallet().client().clearNextError();
        }

        String sseStatusUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/cross-device/status?state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8);
        HttpResponse<String> sseResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(sseStatusUrl))
                                .header("Cookie", browserCookieHeader(sseStatusUrl))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(sseResponse.statusCode()).isEqualTo(200);
        assertThat(sseResponse.body()).contains("event:failed");
        assertThat(sseResponse.body()).doesNotContain("event:complete");
        assertThat(extractRedirectUriFromSseResponse(sseResponse.body())).contains("/failed");
    }

    /**
     * A presentation the verifier rejects has to move the browser in the cross-device flow too.
     * The {@code redirect_uri} the response URI returns reaches only the wallet's own user agent
     * on the other device, so the browser learns of the rejection through the SSE stream or not at
     * all.
     */
    @Test
    void crossDeviceRejectedPresentationReturnsBrowserToLoginPage() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "true"));

        String credentialId = wallet().client().getCredentials().get(0).id();
        wallet().client().revokeCredential(credentialId);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getCrossDeviceWalletUrl();

            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);

            // The browser is on the other device, so the wallet gets the same empty object a
            // completed cross-device login returns.
            assertThat(Oid4vpLoginFlowHelper.verifierStatusCode(walletResponse.rawBody()))
                    .as("Cross-device wallet response: %s", walletResponse.rawBody())
                    .isEqualTo(200);
            assertThat(Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody()))
                    .as("Cross-device wallet response: %s", walletResponse.rawBody())
                    .isEqualTo("{}");
            assertThat(walletResponse.redirectUri()).isNull();
            assertLoginFailedBecauseOf("revoked");

            page.waitForURL(
                    url -> url.contains("/failed")
                            || page.locator("a#social-oid4vp").count() > 0,
                    new Page.WaitForURLOptions().setTimeout(30000));
            page.waitForLoadState();
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }

        assertThat(flow.isCallbackUrl(page.url()))
                .as("A rejected presentation must not complete the login")
                .isFalse();
        page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
    }
}
