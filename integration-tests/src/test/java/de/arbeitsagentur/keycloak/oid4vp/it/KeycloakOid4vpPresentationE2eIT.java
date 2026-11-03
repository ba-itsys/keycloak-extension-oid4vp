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
import com.nimbusds.jwt.JWTClaimsSet;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.authentication.Oid4vpPresentationAuthenticatorFactory;
import de.arbeitsagentur.keycloak.oid4vp.authentication.Oid4vpPresentationRequiredAction;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * The {@code oid4vp-presentation} authenticator and required action. The PID identity provider
 * identifies users through its link, and the presentation identity provider has no principal
 * attributes, so its presentations identify nobody.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpPresentationE2eIT extends AbstractOid4vpE2eTest {

    private static final String PRESENTATION_IDP_ALIAS = "pid-presentation";
    private static final String PID_IDP_ALIAS = Oid4vpTestKeycloakSetup.IDP_ALIAS;
    private static final String PASSWORD_AND_PRESENTATION_FLOW = "password-and-presentation";
    private static final String PASSWORD_AND_WALLET_FLOW = "password-and-wallet";
    private static final String WALLET_FLOW = "wallet";
    private static final String ALICE = "alice";
    private static final String BOB = "bob";
    private static final String PASSWORD = "user-password";

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @BeforeEach
    void setUpPresentation() {
        ensurePresentationIdentityProvider();
        deleteAllOid4vpUsers();
        ensureUser(ALICE);
        ensureUser(BOB);
        ensureFlow(PASSWORD_AND_PRESENTATION_FLOW, PRESENTATION_IDP_ALIAS, "auth-username-password-form");
        ensureFlow(PASSWORD_AND_WALLET_FLOW, PID_IDP_ALIAS, "auth-username-password-form");
        ensureFlow(WALLET_FLOW, PID_IDP_ALIAS);
        Oid4vpTestKeycloakSetup.configurePresentationRequiredAction(
                realm.admin(), Map.of(Oid4vpPresentationAuthenticatorFactory.IDENTITY_PROVIDER, PID_IDP_ALIAS));
        useBrowserFlow(null);
        testApp().reset();
        flow.clearBrowserSession();
    }

    @Test
    void authenticatorKeepsTheClaimsOfAPresentationThatIdentifiesNobody() throws Exception {
        useBrowserFlow(PASSWORD_AND_PRESENTATION_FLOW);
        flow.navigateToLoginPage();
        loginWithPassword(ALICE);

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(page.locator("a#social-oid4vp").count())
                .as("the wallet page of a presentation offers no other login")
                .isZero();
        page.navigate(flow.submitToWallet(walletUrl).redirectUri());
        flow.assertLoginSucceeded();

        JWTClaimsSet idToken = idTokenOfCompletedLogin().getJWTClaimsSet();
        assertThat(idToken.getStringClaim("preferred_username")).isEqualTo(ALICE);
        assertThat(idToken.getStringClaim("credential_family_name")).isNotBlank();
        assertThat(links(ALICE)).isEmpty();
    }

    @Test
    void authenticatorShowsTheWalletsDecline() {
        useBrowserFlow(PASSWORD_AND_PRESENTATION_FLOW);
        flow.navigateToLoginPage();
        loginWithPassword(ALICE);
        String walletUrl = flow.getSameDeviceWalletUrl();

        wallet().client().setNextError("access_denied", "User denied consent");
        try {
            page.navigate(flow.submitToWallet(walletUrl).redirectUri());
        } finally {
            wallet().client().clearNextError();
        }

        assertErrorPage("The presentation was cancelled in the wallet.");
    }

    @Test
    void requiredActionAsksForItsOwnPresentationAfterTheAuthenticators() {
        Oid4vpTestKeycloakSetup.configurePresentationRequiredAction(
                realm.admin(),
                Map.of(Oid4vpPresentationAuthenticatorFactory.IDENTITY_PROVIDER, PRESENTATION_IDP_ALIAS));
        useBrowserFlow(PASSWORD_AND_PRESENTATION_FLOW);
        flow.navigateToLoginPage(Map.of("kc_action", Oid4vpPresentationRequiredAction.PROVIDER_ID));
        loginWithPassword(ALICE);
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        String requiredActionWalletUrl = flow.getSameDeviceWalletUrl();
        assertThat(page.url()).contains("/login-actions/required-action");
        page.navigate(flow.submitToWallet(requiredActionWalletUrl).redirectUri());
        flow.assertLoginSucceeded();

        assertThat(testApp().lastCallbackUri().toString()).contains("kc_action_status=success");
    }

    @Test
    void identityProviderWithoutPrincipalAttributesRefusesTheLogin() {
        realm.updateIdentityProvider(PRESENTATION_IDP_ALIAS, idp -> idp.setHideOnLogin(false));
        flow.navigateToLoginPage();
        page.locator("a#social-" + PRESENTATION_IDP_ALIAS).click();

        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        assertThat(page.locator("body").textContent()).contains("This wallet presentation cannot be used to log in");
        assertThat(flow.isCallbackUrl(page.url())).isFalse();
    }

    @Test
    void walletPageStartsTheLoginOfAnAlternativeIdentityProvider() {
        realm.updateIdentityProvider(PRESENTATION_IDP_ALIAS, idp -> idp.setHideOnLogin(false));
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.getSameDeviceWalletUrl();

        page.locator("a#social-" + PRESENTATION_IDP_ALIAS).click();

        page.waitForURL("**/broker/" + PRESENTATION_IDP_ALIAS + "/login**");
        assertThat(flow.getSameDeviceWalletUrl()).isNotBlank();
    }

    @Test
    void requiredActionLinksTheWalletSoTheAuthenticatorLogsInWithoutPassword() throws Exception {
        linkWalletTo(ALICE);
        assertThat(links(ALICE))
                .extracting(FederatedIdentityRepresentation::getIdentityProvider)
                .containsExactly(PID_IDP_ALIAS);

        useBrowserFlow(WALLET_FLOW);
        flow.navigateToLoginPage();
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());
        flow.assertLoginSucceeded();

        assertThat(idTokenOfCompletedLogin().getJWTClaimsSet().getStringClaim("preferred_username"))
                .isEqualTo(ALICE);
    }

    @Test
    void walletLinkedByTheRequiredActionLogsInThroughTheIdentityProviderToo() throws Exception {
        linkWalletTo(ALICE);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.waitForLoginCompletion(flow.submitToWallet(flow.getSameDeviceWalletUrl()));
        flow.assertLoginSucceeded();

        assertThat(idTokenOfCompletedLogin().getJWTClaimsSet().getStringClaim("preferred_username"))
                .isEqualTo(ALICE);
    }

    @Test
    void authenticatorAcceptsTheWalletLinkedToTheUserAsSecondFactor() {
        linkWalletTo(ALICE);

        useBrowserFlow(PASSWORD_AND_WALLET_FLOW);
        flow.navigateToLoginPage();
        loginWithPassword(ALICE);
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        flow.assertLoginSucceeded();
    }

    @Test
    void authenticatorRefusesAWalletLinkedToAnotherUser() {
        linkWalletTo(BOB);

        useBrowserFlow(PASSWORD_AND_WALLET_FLOW);
        flow.navigateToLoginPage();
        loginWithPassword(ALICE);
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        assertErrorPage("This wallet credential is linked to another account.");
    }

    @Test
    void authenticatorRefusesAnUnlinkedWallet() {
        useBrowserFlow(WALLET_FLOW);
        flow.navigateToLoginPage();
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        assertErrorPage("This wallet credential is not linked to an account.");
    }

    @Test
    void requiredActionRefusesAWalletLinkedToAnotherUser() {
        linkWalletTo(BOB);

        flow.navigateToLoginPage(Map.of("kc_action", Oid4vpPresentationRequiredAction.PROVIDER_ID));
        loginWithPassword(ALICE);
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());

        assertErrorPage("This wallet credential is linked to another account.");
        assertThat(links(ALICE)).isEmpty();
    }

    private void linkWalletTo(String username) {
        flow.navigateToLoginPage(Map.of("kc_action", Oid4vpPresentationRequiredAction.PROVIDER_ID));
        loginWithPassword(username);
        page.navigate(flow.submitToWallet(flow.getSameDeviceWalletUrl()).redirectUri());
        flow.assertLoginSucceeded();
        testApp().reset();
        flow.clearBrowserSession();
    }

    private void loginWithPassword(String username) {
        page.locator("input[name='username']").fill(username);
        page.locator("input[name='password']").fill(PASSWORD);
        page.locator("input[type='submit'], button[type='submit']").first().click();
    }

    private void assertErrorPage(String message) {
        page.waitForSelector("#kc-error-message", new Page.WaitForSelectorOptions().setTimeout(30000));
        assertThat(page.locator("body").textContent()).contains(message);
        assertThat(flow.isCallbackUrl(page.url())).isFalse();
    }

    private List<FederatedIdentityRepresentation> links(String username) {
        String userId =
                realm.admin().users().searchByUsername(username, true).get(0).getId();
        return realm.admin().users().get(userId).getFederatedIdentity();
    }

    private void ensurePresentationIdentityProvider() {
        boolean exists = realm.admin().identityProviders().findAll().stream()
                .anyMatch(idp -> PRESENTATION_IDP_ALIAS.equals(idp.getAlias()));
        if (exists) {
            return;
        }
        IdentityProviderRepresentation idp =
                Oid4vpTestKeycloakSetup.defaultIdentityProvider(TestCertificates.generateHaipCertificateChainPem());
        idp.setAlias(PRESENTATION_IDP_ALIAS);
        idp.setHideOnLogin(true);
        idp.getConfig().remove(Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES);
        try (Response response = realm.admin().identityProviders().create(idp)) {
            assertThat(response.getStatus()).isEqualTo(201);
        }
        IdentityProviderResource resource = realm.admin().identityProviders().get(PRESENTATION_IDP_ALIAS);
        List<IdentityProviderMapperRepresentation> mappers = new ArrayList<>();
        mappers.add(Oid4vpTestKeycloakSetup.defaultSessionNoteMapper());
        mappers.addAll(Oid4vpTestKeycloakSetup.defaultDcqlMappers());
        for (IdentityProviderMapperRepresentation mapper : mappers) {
            mapper.setIdentityProviderAlias(PRESENTATION_IDP_ALIAS);
            try (Response response = resource.addMapper(mapper)) {
                assertThat(response.getStatus()).isEqualTo(201);
            }
        }
    }

    private void ensureUser(String username) {
        if (!realm.admin().users().searchByUsername(username, true).isEmpty()) {
            return;
        }
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(PASSWORD);
        password.setTemporary(false);
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(username + "@example.com");
        user.setFirstName(username);
        user.setLastName("Example");
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setCredentials(List.of(password));
        try (Response response = realm.admin().users().create(user)) {
            assertThat(response.getStatus()).isEqualTo(201);
        }
    }

    private void ensureFlow(String alias, String identityProviderAlias, String... executionsBefore) {
        AuthenticationManagementResource flows = realm.admin().flows();
        if (flows.getFlows().stream().anyMatch(f -> alias.equals(f.getAlias()))) {
            return;
        }
        AuthenticationFlowRepresentation flowRepresentation = new AuthenticationFlowRepresentation();
        flowRepresentation.setAlias(alias);
        flowRepresentation.setProviderId("basic-flow");
        flowRepresentation.setTopLevel(true);
        flowRepresentation.setBuiltIn(false);
        try (Response response = flows.createFlow(flowRepresentation)) {
            assertThat(response.getStatus()).isEqualTo(201);
        }
        for (String provider : executionsBefore) {
            flows.addExecution(alias, Map.of("provider", provider));
        }
        flows.addExecution(alias, Map.of("provider", Oid4vpPresentationAuthenticatorFactory.PROVIDER_ID));
        for (AuthenticationExecutionInfoRepresentation execution : flows.getExecutions(alias)) {
            execution.setRequirement("REQUIRED");
            flows.updateExecutions(alias, execution);
            if (Oid4vpPresentationAuthenticatorFactory.PROVIDER_ID.equals(execution.getProviderId())) {
                AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
                config.setAlias(alias + "-presentation");
                config.setConfig(
                        Map.of(Oid4vpPresentationAuthenticatorFactory.IDENTITY_PROVIDER, identityProviderAlias));
                try (Response response = flows.newExecutionConfig(execution.getId(), config)) {
                    assertThat(response.getStatus()).isEqualTo(201);
                }
            }
        }
    }

    // Keycloak removes an override whose flow id is blank and keeps the ones a client update leaves out.
    private void useBrowserFlow(String alias) {
        String flowId = alias == null
                ? ""
                : realm.admin().flows().getFlows().stream()
                        .filter(f -> alias.equals(f.getAlias()))
                        .findFirst()
                        .orElseThrow()
                        .getId();
        ClientRepresentation client =
                realm.admin().clients().findByClientId(CLIENT_ID).get(0);
        client.setAuthenticationFlowBindingOverrides(Map.of("browser", flowId));
        realm.admin().clients().get(client.getId()).update(client);
    }
}
