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
import io.github.dominikschlosser.oid4vc.CredentialFormat;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.Test;

class KeycloakOid4vpLoginE2eIT extends AbstractOid4vpE2eTest {

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
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        performSameDeviceLogin("wallet-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void subsequentWalletLoginResolvesExistingUser() throws Exception {
        callback().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);

        flow.assertLoginSucceeded();
    }

    @Test
    void mdocPresentationFlow() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

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
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient(), Oid4vpE2eEnvironment.REALM, mdocDcqlQuery);

        try {
            performSameDeviceLogin("mdoc-wallet-user");
            flow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.configureDcqlQuery(
                    adminClient(), Oid4vpE2eEnvironment.REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    void credentialSetsWithSdJwtAndMdoc() throws Exception {
        callback().reset();
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
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient(), Oid4vpE2eEnvironment.REALM, credentialSetsDcqlQuery);
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);
            performSameDeviceLogin("credset-mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet().client().clearPreferredFormat();
            Oid4vpTestKeycloakSetup.configureDcqlQuery(
                    adminClient(), Oid4vpE2eEnvironment.REALM, buildDefaultDcqlQuery());
        }
    }

    @Test
    void walletErrorAllowsRetry() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        wallet().client().setNextError("access_denied", "User denied consent");

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);

            assertThat(walletResponse.redirectUri()).isNull();
            assertThat(walletResponse.rawBody()).contains("access_denied");
        } finally {
            wallet().client().clearNextError();
        }

        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);
        performSameDeviceLogin("retry-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void loginWithIdTokenSubject() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        Oid4vcContainer idTokenWallet = newWallet("oid4vc-idtoken");
        idTokenWallet.start();

        String idTokenTrustListUrl = "http://oid4vc-idtoken:8085/api/trustlist";
        idpConfig
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.USE_ID_TOKEN_SUBJECT, "true")
                .set(Oid4vpIdentityProviderConfig.TRUST_LIST_URL, idTokenTrustListUrl)
                .apply();

        try {
            Oid4vpLoginFlowHelper idTokenFlow = flowFor(idTokenWallet);
            idTokenFlow.navigateToLoginPage();
            idTokenFlow.clickOid4vpIdpButton();
            String walletUrl = idTokenFlow.getSameDeviceWalletUrl();
            PresentationResponse response = idTokenFlow.submitToWallet(walletUrl);
            idTokenFlow.waitForLoginCompletion(response);
            idTokenFlow.completeFirstBrokerLoginIfNeeded("id-token-user");
            idTokenFlow.assertLoginSucceeded();
        } finally {
            idTokenWallet.stop();
        }
    }

    @Test
    void sdJwtAndMdocResolveToSameBrokeredUser() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        performSameDeviceLogin("sd-jwt-user");
        flow.assertLoginSucceeded();
        assertThat(Oid4vpTestKeycloakSetup.countOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM))
                .isEqualTo(1);

        callback().reset();
        flow.clearBrowserSession();
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            performSameDeviceLogin("mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet().client().clearPreferredFormat();
        }

        assertThat(Oid4vpTestKeycloakSetup.countOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM))
                .isEqualTo(1);
    }
}
