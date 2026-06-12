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
package de.arbeitsagentur.keycloak.oid4vp.conformance.verifier;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.PemUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Serves ETSI trust list JWTs to the Keycloak server under test. Keycloak runs on the host, so
 * the lists are served from a local port.
 */
public final class TrustListServer implements AutoCloseable {

    public static final String PID_LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";

    private static TrustListServer instance;

    private final HttpServer server;
    private final Map<String, String> trustLists = new ConcurrentHashMap<>();

    private TrustListServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    public static synchronized TrustListServer instance() {
        if (instance == null) {
            try {
                instance = new TrustListServer();
            } catch (IOException e) {
                throw new IllegalStateException("Failed to start trust list server", e);
            }
        }
        return instance;
    }

    // Publishes a trust list containing the given certificates and returns its URL
    public String publish(String name, List<String> certificatesPem) {
        String path = "/" + name + ".jwt";
        trustLists.put(path, unsignedTrustListJwt(certificatesPem));
        return "http://localhost:" + server.getAddress().getPort() + path;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String body = trustLists.get(exchange.getRequestURI().getPath());
        if (body == null) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/jwt");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String unsignedTrustListJwt(List<String> certificatesPem) {
        try {
            ObjectNode header = JsonNodeFactory.instance.objectNode();
            header.put("alg", "none");
            header.put("typ", "JWT");

            ObjectNode serviceInformation = JsonNodeFactory.instance.objectNode();
            serviceInformation.put("ServiceTypeIdentifier", PID_LOTE_TYPE + "/Issuance");
            ArrayNode x509Certificates =
                    serviceInformation.putObject("ServiceDigitalIdentity").putArray("X509Certificates");
            for (String certificatePem : certificatesPem) {
                x509Certificates
                        .addObject()
                        .put("val", PemUtils.removeBeginEnd(certificatePem).replaceAll("\\s", ""));
            }

            ObjectNode payload = JsonNodeFactory.instance.objectNode();
            ObjectNode lote = payload.putObject("LoTE");
            ObjectNode listInformation = lote.putObject("ListAndSchemeInformation");
            listInformation.put("LoTEType", PID_LOTE_TYPE);
            listInformation.put(
                    "NextUpdate",
                    ZonedDateTime.now()
                            .plusHours(1)
                            .truncatedTo(ChronoUnit.SECONDS)
                            .toOffsetDateTime()
                            .toString());
            lote.putArray("TrustedEntitiesList")
                    .addObject()
                    .putArray("TrustedEntityServices")
                    .addObject()
                    .set("ServiceInformation", serviceInformation);

            return Base64Url.encode(JsonSerialization.writeValueAsBytes(header))
                    + "."
                    + Base64Url.encode(JsonSerialization.writeValueAsBytes(payload))
                    + ".";
        } catch (IOException e) {
            throw new IllegalStateException("Failed to build trust list JWT", e);
        }
    }
}
