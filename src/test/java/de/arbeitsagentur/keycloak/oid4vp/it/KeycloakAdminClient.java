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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public final class KeycloakAdminClient {
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final String baseUrl;
    private final String username;
    private final String password;
    private String token;

    private KeycloakAdminClient(
            ObjectMapper objectMapper,
            HttpClient httpClient,
            String baseUrl,
            String username,
            String password,
            String token) {
        this.objectMapper = objectMapper;
        this.httpClient = httpClient;
        this.baseUrl = baseUrl;
        this.username = username;
        this.password = password;
        this.token = token;
    }

    public static KeycloakAdminClient login(ObjectMapper objectMapper, String baseUrl, String username, String password)
            throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String token = requestToken(objectMapper, client, baseUrl, username, password);
        return new KeycloakAdminClient(objectMapper, client, baseUrl, username, password, token);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> getJson(String urlOrPath) throws Exception {
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .GET());
        assertThat(response.statusCode())
                .withFailMessage("GET %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isEqualTo(200);
        return objectMapper.readValue(response.body(), Map.class);
    }

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> getJsonList(String urlOrPath) throws Exception {
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .GET());
        assertThat(response.statusCode())
                .withFailMessage("GET %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isEqualTo(200);
        return objectMapper.readValue(response.body(), List.class);
    }

    public void postJson(String urlOrPath, Object body) throws Exception {
        String json = objectMapper.writeValueAsString(body);
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)));
        assertThat(response.statusCode())
                .withFailMessage("POST %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isIn(200, 201, 204);
    }

    void putJson(String urlOrPath, Object body) throws Exception {
        String json = objectMapper.writeValueAsString(body);
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(json)));
        assertThat(response.statusCode())
                .withFailMessage("PUT %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isIn(200, 204);
    }

    void delete(String urlOrPath) throws Exception {
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .DELETE());
        assertThat(response.statusCode())
                .withFailMessage("DELETE %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isIn(200, 204);
    }

    public boolean deleteIfExists(String urlOrPath) throws Exception {
        HttpResponse<String> response = sendAuthenticated(() -> HttpRequest.newBuilder()
                .uri(URI.create(resolve(urlOrPath)))
                .timeout(Duration.ofSeconds(30))
                .DELETE());
        if (response.statusCode() == 404) {
            return false;
        }
        assertThat(response.statusCode())
                .withFailMessage("DELETE %s returned %d: %s", urlOrPath, response.statusCode(), response.body())
                .isIn(200, 204);
        return true;
    }

    String baseUrl() {
        return baseUrl;
    }

    private String resolve(String urlOrPath) {
        if (urlOrPath.startsWith("http://") || urlOrPath.startsWith("https://")) {
            return urlOrPath;
        }
        if (urlOrPath.startsWith("/")) {
            return baseUrl + urlOrPath;
        }
        return baseUrl + "/" + urlOrPath;
    }

    private HttpResponse<String> sendAuthenticated(Supplier<HttpRequest.Builder> builderFactory) throws Exception {
        HttpResponse<String> response = sendOnce(builderFactory, token);
        if (response.statusCode() != 401) {
            return response;
        }

        token = requestToken(objectMapper, httpClient, baseUrl, username, password);
        return sendOnce(builderFactory, token);
    }

    private HttpResponse<String> sendOnce(Supplier<HttpRequest.Builder> builderFactory, String token) throws Exception {
        HttpRequest request = builderFactory
                .get()
                .header("Authorization", "Bearer " + token)
                .header("X-Forwarded-Proto", "https")
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String requestToken(
            ObjectMapper objectMapper, HttpClient httpClient, String baseUrl, String username, String password)
            throws Exception {
        String form = "grant_type=password&client_id=admin-cli&username=" + urlEncode(username) + "&password="
                + urlEncode(password);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("X-Forwarded-Proto", "https")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode())
                .withFailMessage(
                        "Admin token request failed: status=%d body=%s", response.statusCode(), response.body())
                .isEqualTo(200);
        JsonNode node = objectMapper.readTree(response.body());
        return node.get("access_token").asText();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
