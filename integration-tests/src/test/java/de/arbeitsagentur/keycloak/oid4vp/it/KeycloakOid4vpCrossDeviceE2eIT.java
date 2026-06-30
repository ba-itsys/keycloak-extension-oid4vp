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

        flow.waitForSseConnection();
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

        flow.waitForSseConnection();
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

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """;
        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED,
                "true",
                Oid4vpIdentityProviderConfig.DCQL_QUERY,
                mdocDcqlQuery));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        LOG.info("[Test] Cross-device mDoc wallet URL: {}", walletUrl);

        flow.waitForSseConnection();
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

        flow.waitForSseConnection();
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
        String requestHandle = flow.getRequestHandle();

        flow.waitForSseConnection();
        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();
        String sseStatusUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/cross-device/status?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
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
        String requestHandle = flow.getRequestHandle();

        flow.waitForSseConnection();
        page.navigate("about:blank");

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        String sseStatusUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/cross-device/status?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);
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
        String requestHandle = flow.getRequestHandle();

        flow.waitForSseConnection();
        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        // A foreign party can only observe the public request_handle (in the request_uri / SSE URL),
        // not the single-use response_code minted during direct_post. Without it, /complete-auth is
        // rejected at the response_code gate before any browser-session check.
        String completeAuthUrl = keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/complete-auth?request_handle="
                + URLEncoder.encode(requestHandle, StandardCharsets.UTF_8);

        var otherContext = newBrowserContext();
        var otherPage = otherContext.newPage();
        try {
            otherPage.navigate(completeAuthUrl);
            otherPage.waitForLoadState();
            assertThat(otherPage.locator("body").textContent().toLowerCase())
                    .contains("invalid or expired authentication response");
        } finally {
            otherPage.close();
            otherContext.close();
        }
    }
}
