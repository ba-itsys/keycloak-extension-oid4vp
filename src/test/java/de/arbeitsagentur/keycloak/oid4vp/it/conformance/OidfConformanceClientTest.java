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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OidfConformanceClientTest {

    private HttpServer server;
    private URI baseUrl;
    private final AtomicReference<String> lastAuthorizationHeader = new AtomicReference<>();

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/api/plan", this::handlePlan);
        server.createContext("/api/plan/plan-1", this::handleLoadPlan);
        server.createContext("/api/runner", this::handleRunner);
        server.createContext("/api/info/run-1", this::handleInfo);
        server.createContext("/api/log/run-1", this::handleLog);
        server.start();
        baseUrl = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void createsPlanStartsModuleAndLoadsRunInfo() throws Exception {
        OidfConformanceClient client =
                new OidfConformanceClient(HttpClient.newHttpClient(), new ObjectMapper(), baseUrl, "api-token");
        OidfConformanceVariant variant = new OidfConformanceVariant(
                OidfConformanceVariant.OidfConformanceCredentialFormat.SD_JWT_VC,
                Oid4vpClientIdScheme.X509_SAN_DNS,
                OidfConformanceVariant.OidfConformanceRequestMethod.REQUEST_URI_SIGNED,
                Oid4vpResponseMode.DIRECT_POST_JWT);

        OidfConformanceClient.ConformancePlan plan =
                client.createPlan("oid4vp-1final-verifier-test-plan", variant, Map.of("alias", "demo"));
        OidfConformanceClient.ConformanceRunStart run =
                client.startModule(plan.id(), plan.modules().get(0).name());
        OidfConformanceClient.ConformanceRunInfo info = client.loadRunInfo(run.runId());

        assertThat(lastAuthorizationHeader.get()).isEqualTo("Bearer api-token");
        assertThat(plan.modules())
                .extracting(OidfConformanceClient.ConformanceModule::name)
                .containsExactly("module-a");
        assertThat(run.runUrl()).hasToString("https://suite.example/authorize");
        assertThat(info.authorizationEndpoint()).hasToString("https://suite.example/authorize");
        assertThat(client.loadRunLog(run.runId())).containsExactly("INFO waiting");
    }

    private void handlePlan(HttpExchange exchange) throws IOException {
        lastAuthorizationHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
        if ("POST".equals(exchange.getRequestMethod())) {
            String query = exchange.getRequestURI().getRawQuery();
            assertThat(query).contains("planName=oid4vp-1final-verifier-test-plan");
            String encodedVariant = query.substring(query.indexOf("variant=") + "variant=".length());
            String variantJson = URLDecoder.decode(encodedVariant, StandardCharsets.UTF_8);
            assertThat(variantJson).contains("\"credential_format\":\"sd_jwt_vc\"");
            assertThat(variantJson).contains("\"client_id_prefix\":\"x509_san_dns\"");
            assertThat(variantJson).contains("\"response_mode\":\"direct_post.jwt\"");
            respond(exchange, 200, "{\"id\":\"plan-1\"}");
            return;
        }
        respond(exchange, 404, "{}");
    }

    private void handleLoadPlan(HttpExchange exchange) throws IOException {
        respond(exchange, 200, """
                {
                  "id": "plan-1",
                  "planName": "oid4vp-1final-verifier-test-plan",
                  "modules": [
                    { "testModule": "module-a" }
                  ]
                }
                """);
    }

    private void handleRunner(HttpExchange exchange) throws IOException {
        respond(exchange, 200, "{\"id\":\"run-1\",\"url\":\"https://suite.example/authorize\"}");
    }

    private void handleInfo(HttpExchange exchange) throws IOException {
        respond(
                exchange,
                200,
                "{\"status\":\"WAITING\",\"result\":\"\",\"exported\":{\"authorization_endpoint\":\"https://suite.example/authorize\"}}");
    }

    private void handleLog(HttpExchange exchange) throws IOException {
        respond(exchange, 200, "[{\"result\":\"INFO\",\"msg\":\"waiting\"}]");
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
        } finally {
            exchange.close();
        }
    }
}
