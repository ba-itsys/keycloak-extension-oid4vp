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

import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

@KeycloakIntegrationTest(config = KeycloakOid4vpThemeE2eIT.ThemeServerConfig.class)
class KeycloakOid4vpThemeE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void namedThemeWithoutParentOverridesExtensionTemplate() {
        openWalletLoginWithTheme("oid4vp-standalone");

        assertThat(page.locator("#custom-oid4vp-page").textContent()).isEqualTo("Standalone wallet login");
        assertThat(flow.getSameDeviceWalletUrl()).contains("request_uri=");
    }

    @Test
    void namedThemeCanReuseExtensionLayoutAndKeycloakV2Imports() {
        openWalletLoginWithTheme("oid4vp-custom-v2");

        assertThat(page.locator("#kc-page-title").textContent()).contains("Custom wallet login");
        assertThat(page.locator("#custom-oid4vp-page").textContent()).isEqualTo("Custom wallet content");
        assertThat(flow.getSameDeviceWalletUrl()).contains("request_uri=");
        assertThat(page.locator("script[src$='/js/oid4vp-template.js']").count())
                .isEqualTo(1);
    }

    @Test
    void templateOutsideLoginDirectoryFallsBackToExtensionPage() {
        openWalletLoginWithTheme("oid4vp-misplaced");

        assertThat(page.locator("#custom-oid4vp-page").count()).isZero();
        assertThat(page.locator("#kc-page-title").textContent()).contains("Sign in with Wallet");
        assertThat(flow.getSameDeviceWalletUrl()).contains("request_uri=");
        assertThat(page.locator("#oid4vp-cross-device-sse-config").count()).isEqualTo(1);
    }

    private void openWalletLoginWithTheme(String theme) {
        realm.updateWithCleanup(config -> config.update(representation -> representation.setLoginTheme(theme)));
        flow.clearBrowserSession();
        // Enter the broker page directly so the standalone fixture only needs the template under test.
        flow.navigateToLoginPage(Map.of("kc_idp_hint", Oid4vpTestKeycloakSetup.IDP_ALIAS));
    }

    public static class ThemeServerConfig extends Oid4vpServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return super.configure(config).dependencyCurrentProject();
        }
    }
}
