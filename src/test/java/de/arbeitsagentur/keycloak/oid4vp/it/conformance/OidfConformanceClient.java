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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

final class OidfConformanceClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI baseUrl;
    private final String apiKey;

    OidfConformanceClient(HttpClient httpClient, ObjectMapper objectMapper, URI baseUrl, String apiKey) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.apiKey = apiKey;
    }

    ConformancePlan createPlan(String planName, OidfConformanceVariant variant, Map<String, Object> config)
            throws IOException, InterruptedException {
        String variantJson = objectMapper.writeValueAsString(variant.toQueryParameters());
        URI uri = URI.create(baseUrl + "/api/plan?planName=" + encode(planName) + "&variant=" + encode(variantJson));
        JsonNode node = sendJson(uri, "POST", objectMapper.writeValueAsString(config));
        String id = firstNonBlank(node.path("id").asText(null), node.path("_id").asText(null));
        if (id == null) {
            throw new IllegalStateException("OIDF conformance suite did not return a plan id");
        }
        return loadPlan(id);
    }

    ConformancePlan loadPlan(String planId) throws IOException, InterruptedException {
        JsonNode node = sendJson(URI.create(baseUrl + "/api/plan/" + encode(planId)), "GET", null);
        String id = firstNonBlank(node.path("id").asText(null), node.path("_id").asText(null));
        List<ConformanceModule> modules = new ArrayList<>();
        if (node.path("modules").isArray()) {
            for (JsonNode moduleNode : node.path("modules")) {
                String moduleName = firstNonBlank(
                        moduleNode.path("testModule").asText(null),
                        moduleNode.path("name").asText(null));
                if (moduleName != null) {
                    modules.add(new ConformanceModule(moduleName));
                }
            }
        }
        return new ConformancePlan(id, node.path("planName").asText(null), modules);
    }

    ConformanceRunStart startModule(String planId, String moduleName) throws IOException, InterruptedException {
        URI uri = URI.create(baseUrl + "/api/runner?test=" + encode(moduleName) + "&plan=" + encode(planId));
        JsonNode node = sendJson(uri, "POST", "");
        String runId =
                firstNonBlank(node.path("id").asText(null), node.path("_id").asText(null));
        if (runId == null) {
            throw new IllegalStateException("OIDF conformance suite did not return a run id");
        }
        String maybeUrl = firstNonBlank(
                node.path("url").asText(null), node.path("testUrl").asText(null));
        return new ConformanceRunStart(runId, maybeUrl != null ? URI.create(maybeUrl) : null);
    }

    ConformanceRunInfo loadRunInfo(String runId) throws IOException, InterruptedException {
        JsonNode node = sendJson(URI.create(baseUrl + "/api/info/" + encode(runId)), "GET", null);
        JsonNode exported = node.path("exported");
        String authorizationEndpoint = null;
        if (exported.isObject()) {
            authorizationEndpoint = exported.path("authorization_endpoint").asText(null);
        }
        return new ConformanceRunInfo(
                node.path("status").asText(null),
                node.path("result").asText(null),
                authorizationEndpoint != null && !authorizationEndpoint.isBlank()
                        ? URI.create(authorizationEndpoint)
                        : null);
    }

    List<String> loadRunLog(String runId) throws IOException, InterruptedException {
        JsonNode node = sendJson(URI.create(baseUrl + "/api/log/" + encode(runId)), "GET", null);
        List<String> lines = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode entry : node) {
                String result = entry.path("result").asText("");
                String message = entry.path("msg").asText("");
                String line = (result.isBlank() ? "" : result + " ") + message;
                if (!line.isBlank()) {
                    lines.add(line);
                }
            }
        }
        return lines;
    }

    void deletePlan(String planId) throws IOException, InterruptedException {
        sendJson(URI.create(baseUrl + "/api/plan/" + encode(planId)), "DELETE", null);
    }

    private JsonNode sendJson(URI uri, String method, String body) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + apiKey);
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        switch (method) {
            case "GET" -> request.GET();
            case "POST" -> request.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
            case "DELETE" -> request.DELETE();
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        }
        HttpResponse<String> response = httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("OIDF conformance call failed: " + method + " " + uri + " -> HTTP "
                    + response.statusCode() + " body=" + response.body());
        }
        return response.body() == null || response.body().isBlank()
                ? objectMapper.createObjectNode()
                : objectMapper.readTree(response.body());
    }

    private static URI normalizeBaseUrl(URI baseUrl) {
        String value = baseUrl.toString();
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return URI.create(value);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    record ConformancePlan(String id, String planName, List<ConformanceModule> modules) {}

    record ConformanceModule(String name) {}

    record ConformanceRunStart(String runId, URI runUrl) {}

    record ConformanceRunInfo(String status, String result, URI authorizationEndpoint) {}
}
