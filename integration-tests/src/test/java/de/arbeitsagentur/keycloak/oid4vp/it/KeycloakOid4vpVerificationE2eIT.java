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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpRejectionResponse;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import io.github.dominikschlosser.eudi.CredentialFormat;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpVerificationE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void revokedSdJwtCredentialIsRejected() throws Exception {
        assertRevokedCredentialIsRejected("SD-JWT");
    }

    @Test
    void revokedMdocCredentialIsRejected() throws Exception {
        replaceDcqlMappers(Oid4vpTestKeycloakSetup.mdocPidMappers());
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            assertRevokedCredentialIsRejected("mDoc", "eu.europa.ec.eudi.pid.1");
        } finally {
            wallet().client().clearPreferredFormat();
        }
    }

    @Test
    void trustListCacheDoesNotBypassSigningCertChanges() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("trustlist-cache-user");
        flow.assertLoginSucceeded();

        KeyPair wrongKeyPair = TestCertificates.generateEcKeyPair();
        X509Certificate wrongCert = TestCertificates.generateCaCert(wrongKeyPair);
        String wrongCertPem = TestCertificates.toPem("CERTIFICATE", wrongCert.getEncoded());
        setTrustIdpConfig(Map.of(EtsiTrustListIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM, wrongCertPem));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        // With the trust list unverifiable, the credential has no trust anchors left: verification
        // fails with "No trusted keys available for ... signature verification" (or "no trusted
        // key matched"), which the login event records as the error_description.
        assertLoginFailed(walletResponse, "no trusted key");
    }

    @Test
    void trustListLoTETypeMismatchIsRejected() throws Exception {
        setTrustIdpConfig(Map.of(
                EtsiTrustListIdentityProviderConfig.TRUST_LIST_LOTE_TYPE,
                "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        // The trust material provider rejects the list with "Trust list LoTE type mismatch:
        // expected ... but got ..." (EtsiTrustListIdentityProvider), which the login event records
        // as the error_description.
        assertLoginFailed(walletResponse, "lote type mismatch");
    }

    @Test
    void activeCredentialPassesStatusListVerification() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("statuslist-active-user");
        flow.assertLoginSucceeded();
    }

    /**
     * A presentation the verifier rejects travelled the back channel, so nothing brings the
     * End-User back unless the response URI hands them a {@code redirect_uri} to follow. They have
     * to arrive on the login page knowing the presentation was rejected, and the attempt they were
     * in the middle of has to be over.
     */
    @Test
    void aRejectedPresentationReturnsTheEndUserToTheLoginPage() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String credentialId = wallet().client().getCredentials().get(0).id();
        wallet().client().revokeCredential(credentialId);

        String walletUrl;
        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            walletUrl = flow.getSameDeviceWalletUrl();
            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);

            assertThat(Oid4vpLoginFlowHelper.verifierStatusCode(walletResponse.rawBody()))
                    .as(
                            "A wallet aborts on a non-2xx status and never follows the redirect. Wallet response: %s",
                            walletResponse.rawBody())
                    .isEqualTo(200);

            assertThat(walletResponse.redirectUri())
                    .as("A rejected presentation must hand the End-User back to the front channel")
                    .isNotNull()
                    .contains("/failed")
                    .contains("response_code=");
            // What was wrong with the presentation stays server-side, so nobody posting to a known
            // state can choose what the browser is shown.
            assertThat(walletResponse.redirectUri()).doesNotContain("revoked");
            assertThat(Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody()))
                    .as("Wallet response: %s", walletResponse.rawBody())
                    .contains("redirect_uri")
                    .doesNotContain("error")
                    .doesNotContain("revoked");
            assertLoginFailedBecauseOf("revoked");

            page.navigate(walletResponse.redirectUri());
            page.waitForLoadState();
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }

        assertThat(flow.isCallbackUrl(page.url()))
                .as("A rejected presentation must not complete the login")
                .isFalse();
        page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
        assertThat(page.locator("body").textContent())
                .as("The login page has to name that the presentation was rejected")
                .contains("could not be verified");

        assertThat(requestObjectResponse(walletUrl).statusCode())
                .as("The rejected attempt is over, so its request object is gone")
                .isEqualTo(404);
    }

    /**
     * The first failure recorded for a login owns the URL handed out with it. A second presentation
     * for the same state, which anyone knowing the public state can post, must not leave the
     * End-User holding a URL that no longer resolves.
     */
    @Test
    void aSecondRejectionKeepsTheFirstFailureUrlValid() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String credentialId = wallet().client().getCredentials().get(0).id();
        wallet().client().revokeCredential(credentialId);

        String firstUrl;
        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();

            firstUrl = flow.submitToWallet(walletUrl).redirectUri();
            String secondUrl = flow.submitToWallet(walletUrl).redirectUri();

            assertThat(secondUrl)
                    .as("A repeated rejection must not replace the URL the End-User already holds")
                    .isEqualTo(firstUrl);
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }

        page.navigate(firstUrl);
        page.waitForLoadState();

        assertThat(flow.isCallbackUrl(page.url())).isFalse();
        page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
        assertThat(page.locator("body").textContent())
                .as("The URL handed out first still ends the login it belongs to")
                .contains("could not be verified");
    }

    /**
     * The failure record is single-use, so a reload of the page the End-User was handed back to
     * finds nothing. The browser opened it, so it gets Keycloak's error page rather than JSON.
     */
    @Test
    void revisitingTheFailureUrlRendersTheErrorPage() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String credentialId = wallet().client().getCredentials().get(0).id();
        wallet().client().revokeCredential(credentialId);

        String redirectUri;
        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            redirectUri = flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri();
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }

        page.navigate(redirectUri);
        page.waitForLoadState();
        page.navigate(redirectUri);
        page.waitForLoadState();

        assertThat(page.locator("body").textContent().toLowerCase())
                .as("URL: %s", page.url())
                .contains("this login has ended");
        assertThat(flow.isCallbackUrl(page.url())).isFalse();
    }

    /** A browser reaching the failure endpoint without parameters gets the error page too. */
    @Test
    void openingTheFailureUrlWithoutParametersRendersTheErrorPage() {
        page.navigate(responseUri() + "/failed");
        page.waitForLoadState();

        assertThat(page.locator("body").textContent().toLowerCase()).contains("this login link is not valid");
    }

    /**
     * A deployment can have the rejection reported to the wallet instead, which OID4VP 1.0 §8.2
     * permits as well. The End-User still reaches the login page, because the error travels beside
     * the {@code redirect_uri} rather than replacing it.
     */
    @Test
    void configuredRejectionResponseReportsTheErrorToTheWallet() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        setIdpConfig(
                Map.of(Oid4vpIdentityProviderConfig.REJECTION_RESPONSE, Oid4vpRejectionResponse.ERROR.configValue()));

        String credentialId = wallet().client().getCredentials().get(0).id();
        wallet().client().revokeCredential(credentialId);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);

            assertThat(Oid4vpLoginFlowHelper.verifierStatusCode(walletResponse.rawBody()))
                    .as("Wallet response: %s", walletResponse.rawBody())
                    .isEqualTo(400);
            String body = Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody());
            assertThat(body).contains("invalid_presentation").contains("revoked");

            // The error travels beside the redirect rather than replacing it, so the End-User still
            // reaches the login page.
            page.navigate(walletResponse.redirectUri());
            page.waitForLoadState();
            assertThat(flow.isCallbackUrl(page.url())).isFalse();
            page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
            assertThat(page.locator("body").textContent()).contains("could not be verified");
            assertLoginFailedBecauseOf("revoked");
        } finally {
            wallet().client().unrevokeCredential(credentialId);
        }
    }

    /**
     * A post naming a login the endpoint cannot resolve gets a plain error and no
     * {@code redirect_uri}: nothing about it proves it came from a wallet, so it must not be able
     * to hand anyone a front-channel URL that ends a login.
     */
    @Test
    void aPostForAnUnknownLoginIsRejectedWithoutARedirect() throws Exception {
        String formBody = "state=" + urlEncode(UUID.randomUUID().toString()) + "&vp_token=" + urlEncode("{}");

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(responseUri()))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode())
                .as("A post naming no live login is not a response this endpoint processed: %s", response.body())
                .isEqualTo(400);
        assertThat(response.body()).contains("session_expired").doesNotContain("redirect_uri");
    }
}
