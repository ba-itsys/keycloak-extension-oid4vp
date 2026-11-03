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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public final class TestCrlServer implements AutoCloseable {

    private static final String PATH = "/ca.crl";

    private final HttpServer server;
    private final AtomicInteger downloads = new AtomicInteger();
    private final CountDownLatch closed = new CountDownLatch(1);
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final byte[] crl;
    private final boolean hang;

    public TestCrlServer(byte[] crl) throws IOException {
        this(crl, false);
    }

    // Answers no request until the server closes.
    public static TestCrlServer hanging() throws IOException {
        return new TestCrlServer(new byte[0], true);
    }

    private TestCrlServer(byte[] crl, boolean hang) throws IOException {
        this.crl = crl;
        this.hang = hang;
        server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
        server.createContext(PATH, this::respond);
        server.setExecutor(executor);
        server.start();
    }

    public int downloads() {
        return downloads.get();
    }

    public String url() {
        return "http://localhost:%d%s".formatted(server.getAddress().getPort(), PATH);
    }

    @Override
    public void close() {
        closed.countDown();
        server.stop(0);
        executor.shutdown();
    }

    private void respond(HttpExchange exchange) throws IOException {
        downloads.incrementAndGet();
        if (hang) {
            try {
                closed.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }
        exchange.getResponseHeaders().add("Content-Type", "application/pkix-crl");
        exchange.sendResponseHeaders(200, crl.length);
        try (OutputStream responseBody = exchange.getResponseBody()) {
            responseBody.write(crl);
        }
    }
}
