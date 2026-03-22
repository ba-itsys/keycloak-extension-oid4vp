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

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class KeycloakOid4vpRequestObjectE2eIT extends AbstractOid4vpE2eTest {

    private static final int DIRECT_POST_ATTEMPTS = 2;
    private static final long DIRECT_POST_RETRY_DELAY_MS = 200L;

    @Test
    void requestObjectCanBeFetchedMultipleTimes() throws Exception {
        callback().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response1 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response2 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response3 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response1.statusCode()).isEqualTo(200);
        assertThat(response2.statusCode()).isEqualTo(200);
        assertThat(response3.statusCode()).isEqualTo(200);

        String kid1 = Oid4vpLoginFlowHelper.extractEncryptionKid(response1.body());
        String kid2 = Oid4vpLoginFlowHelper.extractEncryptionKid(response2.body());
        String kid3 = Oid4vpLoginFlowHelper.extractEncryptionKid(response3.body());
        String nonce1 = Oid4vpLoginFlowHelper.extractRequestClaim(response1.body(), "nonce");
        String nonce2 = Oid4vpLoginFlowHelper.extractRequestClaim(response2.body(), "nonce");
        String nonce3 = Oid4vpLoginFlowHelper.extractRequestClaim(response3.body(), "nonce");
        String state1 = Oid4vpLoginFlowHelper.extractRequestClaim(response1.body(), "state");
        String state2 = Oid4vpLoginFlowHelper.extractRequestClaim(response2.body(), "state");
        String state3 = Oid4vpLoginFlowHelper.extractRequestClaim(response3.body(), "state");

        assertThat(kid1).isNotNull();
        assertThat(kid2).isNotNull();
        assertThat(kid3).isNotNull();
        assertThat(kid1).isNotEqualTo(kid2).isNotEqualTo(kid3);
        assertThat(kid2).isNotEqualTo(kid3);
        assertThat(nonce1).isNotEqualTo(nonce2).isNotEqualTo(nonce3);
        assertThat(state1).isNotEqualTo(state2).isNotEqualTo(state3);
    }

    @Test
    void loginSucceedsAfterMultipleRequestObjectFetches() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> prefetch1 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> prefetch2 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(prefetch1.statusCode()).isEqualTo(200);
        assertThat(prefetch2.statusCode()).isEqualTo(200);

        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("multi-fetch-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void completedFlowInvalidatesRequestUri() throws Exception {
        callback().reset();
        flow.clearBrowserSession();
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient(), Oid4vpE2eEnvironment.REALM);

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();

        Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("earlier-ro-user");
        flow.assertLoginSucceeded();

        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> postLoginFetch = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(postLoginFetch.statusCode()).isEqualTo(404);
        assertThat(postLoginFetch.body()).contains("Request handle not found or expired");
    }

    @Test
    void encryptedDirectPostWithStateIsDecrypted() throws Exception {
        callback().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> requestObjectResponse = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(requestObjectResponse.statusCode()).isEqualTo(200);

        SignedJWT requestObject = SignedJWT.parse(requestObjectResponse.body());
        String state = requestObject.getJWTClaimsSet().getStringClaim("state");
        @SuppressWarnings("unchecked")
        Map<String, Object> clientMetadata =
                (Map<String, Object>) requestObject.getJWTClaimsSet().getClaim("client_metadata");
        assertThat(clientMetadata.keySet())
                .containsExactly("jwks", "encrypted_response_enc_values_supported", "vp_formats_supported");
        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) clientMetadata.get("jwks");
        @SuppressWarnings("unchecked")
        Map<String, Object> publicJwk = ((List<Map<String, Object>>) jwks.get("keys")).get(0);
        assertThat(publicJwk.get("alg")).isEqualTo("ECDH-ES");
        ECKey encryptionKey = ECKey.parse(publicJwk);

        String encryptedResponse = encryptWalletResponse(
                encryptionKey, Map.of("error", "access_denied", "error_description", "wallet rejected"));
        String endpointUri = requestUri.replaceFirst("/request-object/[^/?]+.*$", "");
        String formBody = "state=" + urlEncode(state) + "&response=" + urlEncode(encryptedResponse);

        HttpResponse<String> directPostResponse = postDirectPostWithRetry(httpClient, endpointUri, formBody);

        assertThat(directPostResponse.statusCode()).isEqualTo(200);
        assertThat(directPostResponse.body())
                .contains("redirect_uri")
                .contains("access_denied")
                .doesNotContain("Encrypted response expected");
    }

    private HttpResponse<String> postDirectPostWithRetry(HttpClient httpClient, String endpointUri, String formBody)
            throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpointUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();

        HttpResponse<String> response = null;
        for (int attempt = 1; attempt <= DIRECT_POST_ATTEMPTS; attempt++) {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (!isSessionExpiredResponse(response) || attempt == DIRECT_POST_ATTEMPTS) {
                return response;
            }
            Thread.sleep(DIRECT_POST_RETRY_DELAY_MS);
        }

        return response;
    }

    private boolean isSessionExpiredResponse(HttpResponse<String> response) {
        return response.statusCode() == 400
                && response.body() != null
                && response.body().contains("\"error\":\"session_expired\"");
    }
}
