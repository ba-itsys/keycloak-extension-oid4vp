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
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * Documents the intended level of authentication usage pattern. The client maps the STORK QAA ACR
 * values to levels 3 and 4 ({@code acr.loa.map} in {@link Oid4vpRealmConfig}) while the identity
 * provider caps the cross-device flow at level 3, so a request for level 3 offers both flows and a
 * request for level 4 only the same-device one. The eIDAS LoA mapper writes the level configured for
 * the flow the presentation finished in into the session, from where the client's user session note
 * protocol mapper carries it into the id token.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpLevelOfAuthenticationE2eIT extends AbstractOid4vpE2eTest {

    private static final String STORK_LEVEL_3 = "STORK-QAA-Level-3";
    private static final String STORK_LEVEL_4 = "STORK-QAA-Level-4";

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void level3RequestOffersBothFlowsAndCrossDeviceLoginCarriesStorkLevel3IntoTheIdToken() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_MAX_LOA, "3"));
        addIdpMapper(Oid4vpTestKeycloakSetup.eidasLoaMapper());

        flow.navigateToLoginPage(Map.of("acr_values", STORK_LEVEL_3));
        flow.clickOid4vpIdpButton();

        flow.getSameDeviceWalletUrl();
        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(flow.getCrossDeviceWalletUrl());
        assertThat(walletResponse.redirectUri()).isNull();
        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("stork-level-3-user");
        flow.assertLoginSucceeded();

        SignedJWT idToken = idTokenOfCompletedLogin();
        assertThat(idToken.getJWTClaimsSet().getStringClaim("presentation_flow"))
                .isEqualTo("cross_device");
        assertThat(idToken.getJWTClaimsSet().getStringClaim("eidas_loa")).isEqualTo(STORK_LEVEL_3);
    }

    @Test
    void level4RequestOffersOnlySameDeviceAndLoginCarriesStorkLevel4IntoTheIdToken() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_MAX_LOA, "3"));
        addIdpMapper(Oid4vpTestKeycloakSetup.eidasLoaMapper());

        flow.navigateToLoginPage(Map.of("acr_values", STORK_LEVEL_4));
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(page.locator("#oid4vp-qr-code").count())
                .as("the cross-device QR code is not offered above its LoA ceiling")
                .isZero();

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(walletResponse);
        flow.completeFirstBrokerLoginIfNeeded("stork-level-4-user");
        flow.assertLoginSucceeded();

        SignedJWT idToken = idTokenOfCompletedLogin();
        assertThat(idToken.getJWTClaimsSet().getStringClaim("presentation_flow"))
                .isEqualTo("same_device");
        assertThat(idToken.getJWTClaimsSet().getStringClaim("eidas_loa")).isEqualTo(STORK_LEVEL_4);
    }

    @Test
    void loginEndsOnAnErrorPageWhenNoFlowIsOfferedAtTheRequestedLevel() {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.SAME_DEVICE_MAX_LOA, "3",
                Oid4vpIdentityProviderConfig.CROSS_DEVICE_MAX_LOA, "3"));

        flow.navigateToLoginPage(Map.of("acr_values", STORK_LEVEL_4));
        flow.clickOid4vpIdpButton();

        page.waitForSelector("#kc-error-message", new Page.WaitForSelectorOptions().setTimeout(30000));
        assertThat(page.locator("body").textContent())
                .contains("not available for the requested level of authentication");
    }

    @Test
    void requestWithoutALevelOffersBothFlowsDespiteTheCeiling() {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.CROSS_DEVICE_MAX_LOA, "3"));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        flow.getSameDeviceWalletUrl();
        flow.getCrossDeviceWalletUrl();
    }
}
