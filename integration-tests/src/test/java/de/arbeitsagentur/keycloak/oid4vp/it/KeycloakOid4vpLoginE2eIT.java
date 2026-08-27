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
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import io.github.dominikschlosser.eudi.CredentialFormat;
import io.github.dominikschlosser.eudi.IssueRequest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpLoginE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void loginPageShowsWalletIdpButton() {
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        page.waitForSelector("#username, a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("Expected OID4VP IdP link on login page")
                .isGreaterThan(0);
    }

    @Test
    void firstWalletLoginCreatesNewUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("wallet-user");
        flow.assertLoginSucceeded();
        assertThat(countOid4vpUsers()).isEqualTo(1);
    }

    @Test
    void transientWalletLoginSucceedsWithoutPersistingUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        replaceDcqlMappers(Oid4vpTestKeycloakSetup.sdJwtPidMappers());
        // A transient login reads no claim of the presentation, so the credential carries no
        // identifier the verifier could bind to
        setIdpConfig(Map.of(IdentityProviderModel.DO_NOT_STORE_USERS, "true"));

        performSameDeviceLogin("transient-wallet-user");
        flow.assertLoginSucceeded();

        assertThat(countOid4vpUsers()).isZero();
    }

    /**
     * With transient users the subject never comes from the presentation, so the configuration that
     * names where to read it from is not needed. Leaving {@code principalAttributes} empty must
     * both save and log in: requiring it would force operators to configure a claim that is then
     * ignored, and would reject a valid transient-only verifier at save time.
     */
    @Test
    void transientLoginNeedsNoPrincipalAttributes() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        replaceDcqlMappers(Oid4vpTestKeycloakSetup.sdJwtPidMappers());
        setIdpConfig(Map.of(
                IdentityProviderModel.DO_NOT_STORE_USERS,
                "true",
                Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES,
                ""));

        performSameDeviceLogin("transient-without-principal-attributes");
        flow.assertLoginSucceeded();

        assertThat(countOid4vpUsers()).isZero();
    }

    @Test
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // The first login creates the brokered user through first-broker-login
        performSameDeviceLogin("subsequent-login-user");
        flow.assertLoginSucceeded();
        assertThat(countOid4vpUsers()).isEqualTo(1);

        testApp().reset();
        flow.clearBrowserSession();

        // The second login resolves the existing brokered user instead of creating another one
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);

        flow.assertLoginSucceeded();
        assertThat(countOid4vpUsers()).isEqualTo(1);
    }

    @Test
    void oid4vpLoginPageDoesNotListWalletAsAlternativeMethod() {
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        page.waitForSelector("#oid4vp-open-wallet", new Page.WaitForSelectorOptions().setTimeout(30000));

        assertThat(page.locator("a#social-oid4vp").count())
                .as("OID4VP login page must not offer the active wallet broker as an alternative method")
                .isZero();
    }

    @Test
    void mdocPresentationFlow() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        replaceDcqlMappers(Oid4vpTestKeycloakSetup.mdocPidMappers());

        performSameDeviceLogin("mdoc-wallet-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void credentialSetsWithSdJwtAndMdoc() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        // The default mappers request SD-JWT PID or mDoc PID as alternative credential set options.
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            deleteAllOid4vpUsers();
            performSameDeviceLogin("credset-mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet().client().clearPreferredFormat();
        }
    }

    @Test
    void walletErrorAllowsRetry() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        wallet().client().setNextError("access_denied", "User denied consent");

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);

            // OID4VP 1.0 §8.2 lets the response URI answer an Authorization Error Response with a
            // redirect_uri, and the wallet MUST follow it. Without one the wallet has nowhere to
            // send the End-User and the login stalls with the browser still on the wallet page.
            assertThat(Oid4vpLoginFlowHelper.verifierResponseBody(walletResponse.rawBody()))
                    .contains("redirect_uri")
                    .doesNotContain("access_denied");
            assertThat(walletResponse.redirectUri())
                    .as("A declined presentation must hand the End-User back to the front channel")
                    .isNotNull()
                    .contains("/failed")
                    .contains("response_code=");

            // The wallet's own error text stays server-side, so a wallet cannot choose what the
            // browser is shown.
            assertThat(walletResponse.redirectUri()).doesNotContain("User denied consent");

            page.navigate(walletResponse.redirectUri());
            page.waitForLoadState();
            assertThat(flow.isCallbackUrl(page.url()))
                    .as("A declined presentation must not complete the login")
                    .isFalse();
            page.waitForSelector("a#social-oid4vp", new Page.WaitForSelectorOptions().setTimeout(30000));
        } finally {
            wallet().client().clearNextError();
        }

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        performSameDeviceLogin("retry-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void sameDeviceCompleteAuthIsRejectedFromDifferentBrowserSession() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        String redirectUri = response.redirectUri();

        assertThat(redirectUri).contains("complete-auth");

        var otherContext = newBrowserContext();
        var otherPage = otherContext.newPage();
        try {
            otherPage.navigate(redirectUri);
            otherPage.waitForLoadState();
            assertThat(otherPage.url()).contains("/broker/oid4vp/endpoint/complete-auth");
            assertThat(otherPage.locator("body").textContent().toLowerCase()).contains("different browser");
        } finally {
            otherPage.close();
            otherContext.close();
        }
    }

    @Test
    void sessionMapperStoresCredentialClaimInSessionAndMapsItToIdToken() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String expectedFamilyName = wallet().client().getCredentials().stream()
                .map(credential -> credential.claims().get("family_name"))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No credential with family_name claim found"));

        performSameDeviceLogin("session-note-user");
        flow.assertLoginSucceeded();

        SignedJWT idToken = idTokenOfCompletedLogin();
        String familyNameFromIdToken = idToken.getJWTClaimsSet().getStringClaim("credential_family_name");
        assertThat(familyNameFromIdToken).isEqualTo(expectedFamilyName);
    }

    @Test
    void twoCredentialOptionImportsClaimsFromEachCredential() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // One option naming both credentials, so the wallet presents the SD-JWT PID and the mDoc
        // PID together. Both carry family_name, so each mapper has to read its own credential.
        setCredentialSets("[{\"options\": [[\"" + Oid4vpTestKeycloakSetup.SD_JWT_PID_CREDENTIAL_ID + "\", \""
                + Oid4vpTestKeycloakSetup.MDOC_PID_CREDENTIAL_ID + "\"]]}]");

        performSameDeviceLogin("two-credential-user");
        flow.assertLoginSucceeded();

        SignedJWT idToken = idTokenOfCompletedLogin();

        assertThat(idToken.getJWTClaimsSet().getStringClaim("sd_jwt_family_name"))
                .as("the SD-JWT mapper imports the family_name of the SD-JWT PID")
                .isNotBlank();
        assertThat(idToken.getJWTClaimsSet().getStringClaim("mdoc_family_name"))
                .as("the mDoc mapper imports the family_name of the mDoc PID")
                .isNotBlank();
    }

    @Test
    void sdJwtAndMdocResolveToSameBrokeredUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("sd-jwt-user");
        flow.assertLoginSucceeded();
        assertThat(countOid4vpUsers()).isEqualTo(1);

        testApp().reset();
        flow.clearBrowserSession();
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            performSameDeviceLogin("mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet().client().clearPreferredFormat();
        }

        assertThat(countOid4vpUsers()).isEqualTo(1);
    }

    /**
     * One rendered wallet page hands out two states a wallet can answer, one behind the button and
     * one behind the QR code, and both stay live until they expire. The login belongs to the
     * presentation the browser completes, so a presentation answering the other state of the same
     * authentication session must not become the identity that signs in.
     */
    @Test
    void aPresentationForAnotherStateDoesNotDecideThisAttemptsLogin() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        replaceDcqlMappers(Oid4vpTestKeycloakSetup.sdJwtPidMappers());

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String buttonWalletUrl = flow.getSameDeviceWalletUrl();
        String qrCodeWalletUrl = flow.getCrossDeviceWalletUrl();
        assertThat(buttonWalletUrl)
                .as("Button and QR code are attempts of their own")
                .isNotEqualTo(qrCodeWalletUrl);

        // Opening the wallet app takes the browser off the page, which is what ends the QR code's
        // event stream: from here on only the button's own redirect brings the End-User back.
        page.navigate("about:blank");

        issueSdJwtPidOf("Holder-Of-Record");
        Oid4vpLoginFlowHelper.WalletResponse decidingResponse = flow.submitToWallet(buttonWalletUrl);
        assertThat(decidingResponse.redirectUri()).contains("complete-auth");

        // Only now is the QR code of the same page answered, by a wallet that meanwhile holds
        // another PID.
        issueSdJwtPidOf("Somebody-Else");
        flow.submitToWallet(qrCodeWalletUrl);

        page.navigate(decidingResponse.redirectUri());
        page.waitForLoadState();
        flow.completeFirstBrokerLoginIfNeeded("other-state-user");
        flow.assertLoginSucceeded();

        SignedJWT idToken =
                SignedJWT.parse(exchangeAuthorizationCode().path("id_token").asText());
        assertThat(idToken.getJWTClaimsSet().getStringClaim("sd_jwt_family_name"))
                .as("The login carries the identity of the presentation it was completed for")
                .isEqualTo("Holder-Of-Record");
    }

    /**
     * A wallet-reported error ends the attempt it belongs to once the End-User has been handed
     * back to the login page. The abandoned state must stop serving its request object rather than
     * stay answerable for the rest of the login timeout.
     */
    @Test
    void aDeclinedPresentationEndsTheAttemptItBelongsTo() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        wallet().client().setNextError("access_denied", "User denied consent");

        String walletUrl;
        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            walletUrl = flow.getSameDeviceWalletUrl();
            assertThat(requestObjectResponse(walletUrl).statusCode())
                    .as("The request object is served while the attempt is live")
                    .isEqualTo(200);

            Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
            page.navigate(walletResponse.redirectUri());
            page.waitForLoadState();
        } finally {
            wallet().client().clearNextError();
        }

        HttpResponse<String> afterDecline = requestObjectResponse(walletUrl);
        assertThat(afterDecline.statusCode())
                .as("The declined attempt is over, so its request object is gone: %s", afterDecline.body())
                .isEqualTo(404);
    }

    /** Puts a single SD-JWT PID carrying the given family name into the wallet. */
    private void issueSdJwtPidOf(String familyName) {
        wallet().client().deleteCredentialsByType(Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT);
        wallet().client()
                .issueCredential(IssueRequest.pid(CredentialFormat.SD_JWT)
                        .claim("family_name", familyName)
                        .claim("given_name", "Erika")
                        .claim("birthdate", "1984-01-26"));
    }

    /**
     * The response URI answers posts. A wallet that redirected an error to it by itself would
     * arrive with nothing proving it is the End-User's browser, and with an error nobody
     * authenticated, so the request must not be answered and the login it names has to survive it.
     */
    @Test
    void aGetOnTheResponseUriDoesNotEndTheLogin() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String state =
                Oid4vpLoginFlowHelper.extractStateFromRequestUri(Oid4vpLoginFlowHelper.extractRequestUri(walletUrl));

        String chosenText = "chosen-by-whoever-knows-the-state";
        String responseUri = responseUri() + "?state=" + urlEncode(state) + "&error=access_denied&error_description="
                + urlEncode(chosenText);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(responseUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode())
                .as("A GET on the response URI is not a login signal: %s", response.body())
                .isGreaterThanOrEqualTo(400);
        assertThat(response.body())
                .as("Nothing a caller wrote may come back rendered")
                .doesNotContain(chosenText);

        // The login it named is untouched and still completes.
        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        page.navigate(walletResponse.redirectUri());
        page.waitForLoadState();
        flow.completeFirstBrokerLoginIfNeeded("response-uri-get-user");
        flow.assertLoginSucceeded();
    }
}
