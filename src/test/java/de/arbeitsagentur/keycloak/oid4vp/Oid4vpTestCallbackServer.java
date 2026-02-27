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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

final class Oid4vpTestCallbackServer implements AutoCloseable {
    private final HttpServer server;
    private final int port;
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile URI lastRequestUri;

    Oid4vpTestCallbackServer() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.port = server.getAddress().getPort();
        server.createContext("/callback", this::handleCallback);
        server.start();
    }

    int port() {
        return port;
    }

    String localCallbackUrl() {
        return "http://localhost:%d/callback".formatted(port);
    }

    int requestCount() {
        return requestCount.get();
    }

    URI lastRequestUri() {
        return lastRequestUri;
    }

    void reset() {
        requestCount.set(0);
        lastRequestUri = null;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handleCallback(HttpExchange exchange) throws IOException {
        requestCount.incrementAndGet();
        lastRequestUri = exchange.getRequestURI();

        String response = "<!doctype html><html><body><pre>OK</pre></body></html>";
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
