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
import com.microsoft.playwright.Page;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import io.github.dominikschlosser.eudi.CredentialFormat;
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
    }

    @Test
    void transientWalletLoginSucceedsWithoutPersistingUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        replaceDcqlMappers(Oid4vpTestKeycloakSetup.sdJwtPidMappers());
        setIdpConfig(Map.of(
                IdentityProviderModel.DO_NOT_STORE_USERS, "true",
                Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTE, "missing_identifier"));

        performSameDeviceLogin("transient-wallet-user");
        flow.assertLoginSucceeded();

        assertThat(countOid4vpUsers()).isZero();
    }

    @Test
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);

        flow.assertLoginSucceeded();
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

            assertThat(walletResponse.rawBody()).contains("access_denied");
            if (walletResponse.redirectUri() != null) {
                assertThat(walletResponse.redirectUri()).contains("access_denied");
            }
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
            assertThat(otherPage.locator("body").textContent().toLowerCase())
                    .contains("authentication session does not match");
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

        JsonNode tokenResponse = exchangeAuthorizationCode();
        String serializedIdToken = tokenResponse.path("id_token").asText();
        assertThat(serializedIdToken).isNotBlank();

        SignedJWT idToken = SignedJWT.parse(serializedIdToken);
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

        JsonNode tokenResponse = exchangeAuthorizationCode();
        SignedJWT idToken = SignedJWT.parse(tokenResponse.path("id_token").asText());

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
}
