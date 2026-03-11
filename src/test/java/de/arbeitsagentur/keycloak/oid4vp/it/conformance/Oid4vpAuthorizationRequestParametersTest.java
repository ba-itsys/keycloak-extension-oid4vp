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
package de.arbeitsagentur.keycloak.oid4vp.it.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.Test;

class Oid4vpAuthorizationRequestParametersTest {

    @Test
    void convertsWalletDeepLinkToHttpsAuthorizationRequest() {
        Oid4vpAuthorizationRequestParameters parameters = Oid4vpAuthorizationRequestParameters.parse(
                "openid4vp://?client_id=x509_san_dns%3Awallet.example&request_uri="
                        + "https%3A%2F%2Fverifier.example%2Frequest-object%2F123");

        URI authorizationRequest = parameters.toAuthorizationEndpoint(URI.create("https://suite.example/authorize"));

        assertThat(authorizationRequest)
                .hasToString("https://suite.example/authorize?client_id=x509_san_dns%3Awallet.example&request_uri="
                        + "https%3A%2F%2Fverifier.example%2Frequest-object%2F123");
    }
}
