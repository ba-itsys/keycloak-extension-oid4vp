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
package de.arbeitsagentur.keycloak.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class ThemeResourcesTest {

    @Test
    void oid4vpTemplatesUseTheLoginThemeLayout() throws Exception {
        assertThat(loadResource("/theme-resources/templates/login-oid4vp-idp.ftl"))
                .contains("<#import \"template.ftl\" as layout>");
        assertThat(loadResource("/theme-resources/templates/login-oid4vp-expired.ftl"))
                .contains("<#import \"template.ftl\" as layout>");
    }

    @Test
    void oid4vpLoginTemplateFiltersCurrentBrokerFromAlternativeMethods() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");

        assertThat(loginTemplate).contains("currentBrokerAlias");
        assertThat(loginTemplate).contains("p.alias != (currentBrokerAlias!'')");
        assertThat(loginTemplate).contains("<#if hasAlternativeProvider>");
    }

    @Test
    void oid4vpLoginTemplateUsesMessageBundleKeysForUserFacingTexts() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");
        Properties messages = loadMessageBundle();

        assertThat(loginTemplate).contains("${msg(\"oid4vpLoginTitle\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpOpenWalletApp\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpScanWithPhone\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpScanWithWalletApp\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpQrCodeAlt\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpAlternativeMethods\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpLinkExpiresIn\")}");
        assertThat(messages.stringPropertyNames())
                .contains(
                        "oid4vpScanWithPhone",
                        "oid4vpScanWithWalletApp",
                        "oid4vpAlternativeMethods",
                        "oid4vpLinkExpiresIn");
        // Keycloak's base login theme supplies these, and its theme messages take precedence.
        assertThat(messages.stringPropertyNames())
                .doesNotContain("oid4vpLoginTitle", "oid4vpOpenWalletApp", "oid4vpQrCodeAlt");
    }

    @Test
    void oid4vpExpiredTemplateUsesMessageBundleKeysForUserFacingTexts() throws Exception {
        String expiredTemplate = loadResource("/theme-resources/templates/login-oid4vp-expired.ftl");
        Properties messages = loadMessageBundle();

        assertThat(expiredTemplate).contains("${msg(\"oid4vpLinkExpiredTitle\")}");
        assertThat(expiredTemplate).contains("${msg(\"oid4vpLinkExpired\")}");
        assertThat(expiredTemplate).contains("${msg(\"oid4vpGetNewLink\")}");
        assertThat(messages.stringPropertyNames())
                .contains("oid4vpLinkExpiredTitle", "oid4vpLinkExpired", "oid4vpGetNewLink");
    }

    @Test
    void messageBundleNamesARejectedPresentation() throws Exception {
        Properties messages = loadMessageBundle();

        assertThat(messages.stringPropertyNames()).contains(Oid4vpMessages.PRESENTATION_REJECTED);
    }

    @Test
    void messageBundleCoversTheErrorPageKeys() throws Exception {
        Properties messages = loadMessageBundle();

        assertThat(messages.stringPropertyNames())
                .contains(
                        Oid4vpMessages.LOGIN_ENDED,
                        Oid4vpMessages.LOGIN_EXPIRED,
                        Oid4vpMessages.INVALID_LOGIN_RESPONSE,
                        Oid4vpMessages.BROWSER_SESSION_MISMATCH,
                        Oid4vpMessages.LOGIN_DATA_MISSING);
    }

    private Properties loadMessageBundle() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = getClass().getResourceAsStream("/theme-resources/messages/messages_en.properties")) {
            assertThat(input).as("message bundle").isNotNull();
            properties.load(input);
        }
        return properties;
    }

    private String loadResource(String resourcePath) throws IOException {
        try (InputStream input = getClass().getResourceAsStream(resourcePath)) {
            assertThat(input).as("resource %s", resourcePath).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
