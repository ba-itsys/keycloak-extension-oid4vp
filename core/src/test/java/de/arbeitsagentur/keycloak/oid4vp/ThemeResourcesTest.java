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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ThemeResourcesTest {

    @Test
    void oid4vpLoginTemplateUsesDedicatedLayoutWithoutGenericAuthChecker() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");
        String layoutTemplate = loadResource("/theme-resources/templates/oid4vp-template.ftl");

        assertThat(loginTemplate).contains("<#import \"oid4vp-template.ftl\" as layout>");
        assertThat(layoutTemplate).doesNotContain("startSessionPolling");
        assertThat(layoutTemplate).doesNotContain("checkAuthSession");
    }

    @Test
    void oid4vpLayoutAvoidsInlineJavaScript() throws Exception {
        String layoutTemplate = loadResource("/theme-resources/templates/oid4vp-template.ftl");

        assertThat(layoutTemplate).doesNotContain("<script type=\"importmap\">");
        assertThat(layoutTemplate).doesNotContain("<script type=\"module\">");
        assertThat(layoutTemplate).doesNotContain("onclick=");
        assertThat(layoutTemplate).doesNotContain("onchange=");
        assertThat(layoutTemplate).doesNotContain("javascript:");
    }

    @Test
    void oid4vpLoginTemplateFiltersCurrentBrokerFromAlternativeMethods() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");

        assertThat(loginTemplate).contains("currentBrokerAlias");
        assertThat(loginTemplate).contains("p.alias != (currentBrokerAlias!'')");
        assertThat(loginTemplate).contains("<#if hasAlternativeProvider>");
    }

    @Test
    void oid4vpLoginTemplateUsesMessageBundleForUserFacingTexts() throws Exception {
        String loginTemplate = loadResource("/theme-resources/templates/login-oid4vp-idp.ftl");
        String messages = loadResource("/theme-resources/messages/messages_en.properties");

        assertThat(loginTemplate).contains("${msg(\"oid4vpLoginTitle\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpOpenWalletApp\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpScanWithPhone\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpScanWithWalletApp\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpQrCodeAlt\")}");
        assertThat(loginTemplate).contains("${msg(\"oid4vpAlternativeMethods\")}");
        assertThat(loginTemplate).doesNotContain("Sign in with Wallet");
        assertThat(loginTemplate).doesNotContain("Open Wallet App");
        assertThat(loginTemplate).doesNotContain("Or scan with your phone:");
        assertThat(loginTemplate).doesNotContain("Scan with your wallet app:");
        assertThat(loginTemplate).doesNotContain("QR Code for wallet login");
        assertThat(loginTemplate).doesNotContain("Or sign in with another method:");

        assertThat(messages).contains("oid4vpLoginTitle=Sign in with Wallet");
        assertThat(messages).contains("oid4vpOpenWalletApp=Open Wallet App");
        assertThat(messages).contains("oid4vpScanWithPhone=Or scan with your phone:");
        assertThat(messages).contains("oid4vpScanWithWalletApp=Scan with your wallet app:");
        assertThat(messages).contains("oid4vpQrCodeAlt=QR Code for wallet login");
        assertThat(messages).contains("oid4vpAlternativeMethods=Or sign in with another method:");
    }

    private String loadResource(String resourcePath) throws IOException {
        try (InputStream input = getClass().getResourceAsStream(resourcePath)) {
            assertThat(input).as("resource %s", resourcePath).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
