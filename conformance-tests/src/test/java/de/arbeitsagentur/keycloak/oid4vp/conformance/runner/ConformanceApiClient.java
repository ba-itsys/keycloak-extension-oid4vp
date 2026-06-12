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
package de.arbeitsagentur.keycloak.oid4vp.conformance.runner;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import org.keycloak.util.JsonSerialization;

// Client for the conformance suite REST API, driving plans and test modules
public final class ConformanceApiClient {

    private final URI baseUri;
    private final HttpClient httpClient;

    // Plans created for a plan variant, keyed by plan name and variant. Discovery creates a plan to
    // read back its modules and the run reuses that same plan, so a plan variant is never
    // provisioned on the suite twice.
    private final Map<String, JsonNode> createdPlans = new ConcurrentHashMap<>();

    public ConformanceApiClient(URI baseUri, SSLContext sslContext) {
        this.baseUri = baseUri;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .sslContext(sslContext)
                .build();
    }

    public void waitUntilAvailable(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        RuntimeException lastFailure = null;
        while (System.nanoTime() < deadline) {
            try {
                HttpResponse<String> response =
                        send(request("/api/runner/available").GET().build());
                if (response.statusCode() == 200) {
                    return;
                }
                lastFailure = new IllegalStateException("Conformance server returned HTTP " + response.statusCode());
            } catch (RuntimeException e) {
                lastFailure = e;
            }
            sleep(Duration.ofSeconds(2));
        }
        throw new IllegalStateException("Conformance server did not become available at " + baseUri, lastFailure);
    }

    // One module of a plan as the suite reports it, with its own variant combination
    public record DiscoveredModule(String name, Map<String, String> variant) {}

    /**
     * Discovers every module and its variant combination from the suite for the given plan
     * variant. The suite is the source of truth for which modules and module variants exist, so a
     * non applicable plan variant yields an empty list rather than fabricated combinations.
     */
    public List<DiscoveredModule> discoverPlanModules(
            String planName, Map<String, String> planVariant, JsonNode suiteConfig) {
        JsonNode plan;
        try {
            plan = getOrCreatePlan(planName, suiteConfig, planVariant);
        } catch (RuntimeException e) {
            // The suite rejects plan variants with no applicable modules
            return List.of();
        }
        List<DiscoveredModule> modules = new ArrayList<>();
        for (JsonNode entry : plan.path("modules")) {
            String name = entry.path("testModule").asText();
            if (!name.isBlank()) {
                modules.add(new DiscoveredModule(name, variantMap(entry.path("variant"))));
            }
        }
        return modules;
    }

    private static Map<String, String> variantMap(JsonNode variant) {
        Map<String, String> map = new LinkedHashMap<>();
        variant.fields()
                .forEachRemaining(
                        field -> map.put(field.getKey(), field.getValue().asText()));
        return map;
    }

    /**
     * Runs one module of a plan. Once the module waits for the verifier, the interaction is
     * invoked with the module info to trigger the authorization request against the suite.
     */
    public ConformanceModuleResult run(
            ConformanceModuleVariant module, JsonNode suiteConfig, VerifierInteraction interaction) {
        JsonNode plan = getOrCreatePlan(module.plan(), suiteConfig, module.planVariant());
        String planId = requiredText(plan, "id");

        JsonNode moduleNode = createModule(planId, module.name(), module.moduleVariant());
        String moduleId = requiredText(moduleNode, "id");
        JsonNode info = waitForState(moduleId, List.of("CONFIGURED", "WAITING", "FINISHED"), Duration.ofMinutes(4));
        if ("CONFIGURED".equals(info.path("status").asText())) {
            startModule(moduleId);
            info = waitForState(moduleId, List.of("WAITING", "FINISHED"), Duration.ofMinutes(4));
        }
        if ("WAITING".equals(info.path("status").asText())) {
            info = waitForExportedAuthorizationEndpoint(moduleId, info);
            interaction.trigger(new ModuleRun(moduleNode, info));
        }
        info = waitForState(moduleId, List.of("FINISHED"), Duration.ofMinutes(8));
        JsonNode logs = getLogs(moduleId);

        return new ConformanceModuleResult(
                module.plan(),
                module.planVariant(),
                module.name(),
                module.moduleVariant(),
                planId,
                moduleId,
                info.path("status").asText(),
                info.path("result").asText("UNKNOWN"),
                logs);
    }

    // Returns the plan for this plan variant, creating it on the suite only the first time. The key
    // excludes the suite config because it is constant for a plan variant apart from a cosmetic alias.
    private JsonNode getOrCreatePlan(String planName, JsonNode suiteConfig, Map<String, String> variants) {
        String key = planName + "|" + (variants == null ? "" : JsonSerialization.valueAsString(variants));
        JsonNode cached = createdPlans.get(key);
        if (cached != null) {
            return cached;
        }
        JsonNode plan = createPlan(planName, suiteConfig, variants);
        createdPlans.put(key, plan);
        return plan;
    }

    private JsonNode createPlan(String planName, JsonNode suiteConfig, Map<String, String> variants) {
        StringBuilder path =
                new StringBuilder("/api/plan?planName=").append(URLEncoder.encode(planName, StandardCharsets.UTF_8));
        if (variants != null && !variants.isEmpty()) {
            path.append("&variant=")
                    .append(URLEncoder.encode(JsonSerialization.valueAsString(variants), StandardCharsets.UTF_8));
        }
        HttpRequest request = request(path.toString())
                .POST(HttpRequest.BodyPublishers.ofString(suiteConfig.toString()))
                .header("Content-Type", "application/json")
                .build();
        return expectJson(request, 201);
    }

    private JsonNode createModule(String planId, String module, Map<String, String> variants) {
        StringBuilder path = new StringBuilder("/api/runner?test=")
                .append(URLEncoder.encode(module, StandardCharsets.UTF_8))
                .append("&plan=")
                .append(URLEncoder.encode(planId, StandardCharsets.UTF_8));
        if (variants != null && !variants.isEmpty()) {
            path.append("&variant=")
                    .append(URLEncoder.encode(JsonSerialization.valueAsString(variants), StandardCharsets.UTF_8));
        }
        return expectJson(
                request(path.toString())
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                201);
    }

    private void startModule(String moduleId) {
        expectJson(
                request("/api/runner/" + moduleId)
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                200);
    }

    private JsonNode waitForState(String moduleId, List<String> states, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        JsonNode lastInfo = null;
        RuntimeException lastFailure = null;
        while (System.nanoTime() < deadline) {
            try {
                lastInfo = getInfo(moduleId);
                String status = lastInfo.path("status").asText();
                // INTERRUPTED is a terminal state too and surfaces as a normal assertion failure downstream
                if (states.contains(status) || "INTERRUPTED".equals(status)) {
                    return lastInfo;
                }
            } catch (RuntimeException e) {
                // Transient failures are tolerated until the deadline
                lastFailure = e;
            }
            sleep(Duration.ofSeconds(1));
        }
        throw new IllegalStateException(
                "Timed out waiting for conformance module " + moduleId + " to reach " + states + ". Last info: "
                        + lastInfo,
                lastFailure);
    }

    // The module exports its authorization endpoint shortly after it starts waiting
    private JsonNode waitForExportedAuthorizationEndpoint(String moduleId, JsonNode lastInfo) {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        JsonNode info = lastInfo;
        while (System.nanoTime() < deadline) {
            if (!info.path("exported").path("authorization_endpoint").asText("").isBlank()) {
                return info;
            }
            sleep(Duration.ofMillis(500));
            info = getInfo(moduleId);
        }
        return info;
    }

    private JsonNode getInfo(String moduleId) {
        return expectJson(request("/api/info/" + moduleId).GET().build(), 200);
    }

    private JsonNode getLogs(String moduleId) {
        return expectJson(request("/api/log/" + moduleId).GET().build(), 200);
    }

    private JsonNode expectJson(HttpRequest request, int expectedStatus) {
        HttpResponse<String> response = send(request);
        if (response.statusCode() != expectedStatus) {
            throw new IllegalStateException("Conformance API " + request.method() + " " + request.uri()
                    + " returned HTTP " + response.statusCode() + ": " + response.body());
        }
        return JsonSerialization.valueFromString(response.body(), JsonNode.class);
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new RuntimeException("Conformance API request failed: " + request.uri(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while calling conformance API: " + request.uri(), e);
        }
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(baseUri.resolve(path))
                .timeout(Duration.ofMinutes(2))
                .header("Accept", "application/json");
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText(null);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Conformance API response missing '" + field + "': " + node);
        }
        return value;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
