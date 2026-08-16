/*
 * Copyright 2025 Bundesagentur für Arbeit
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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Oid4vpWalletAuthorizationUrlTest {

    private static final String CLIENT_ID = "https://verifier.example/realm";
    private static final URI REQUEST_URI = URI.create("https://verifier.example/request-object/abc123");

    private Oid4vpRedirectFlowService service;

    @BeforeEach
    void setUp() {
        service = new Oid4vpRedirectFlowService(null, 300);
    }

    private String build(String walletScheme) {
        return service.buildWalletAuthorizationUrl(walletScheme, CLIENT_ID, REQUEST_URI, false)
                .toString();
    }

    private String buildWithPost(String walletScheme) {
        return service.buildWalletAuthorizationUrl(walletScheme, CLIENT_ID, REQUEST_URI, true)
                .toString();
    }

    @Test
    void customSchemeWithSeparatorIsUsedAsIs() {
        assertThat(build("openid4vp://")).startsWith("openid4vp://?client_id=").contains("&request_uri=");
    }

    @Test
    void customSchemeWithoutSeparatorGetsOneAppended() {
        assertThat(build("haip-vp")).startsWith("haip-vp://?client_id=");
    }

    @Test
    void walletEndpointUrlKeepsPathAndAppendsQuery() {
        assertThat(build("http://localhost:8085/authorize"))
                .startsWith("http://localhost:8085/authorize?client_id=")
                .contains("&request_uri=");
    }

    @Test
    void httpsWalletEndpointUrlKeepsPathAndAppendsQuery() {
        assertThat(build("https://wallet.example.com/authorize"))
                .startsWith("https://wallet.example.com/authorize?client_id=");
    }

    @Test
    void walletEndpointUrlWithQueryAppendsWithAmpersand() {
        assertThat(build("https://wallet.example.com/authorize?tenant=a"))
                .startsWith("https://wallet.example.com/authorize?tenant=a&client_id=");
    }

    @Test
    void bareHttpPrefixIsStillTreatedAsScheme() {
        assertThat(build("http://")).startsWith("http://?client_id=");
    }

    @Test
    void blankSchemeFallsBackToDefault() {
        assertThat(build(" ")).startsWith("openid4vp://?client_id=");
    }

    @Test
    void requestUriMethodPostIsNotAdvertisedByDefault() {
        assertThat(build("openid4vp://")).doesNotContain("request_uri_method");
    }

    @Test
    void requestUriMethodPostIsAdvertisedWhenEnabled() {
        assertThat(buildWithPost("openid4vp://")).contains("&request_uri_method=post");
    }
}
