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
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.protocol.oidc.utils.PkceUtils;

/**
 * The OAuth client application (relying party) the tests log in to. It creates authorization
 * requests (with PKCE), serves the redirect endpoint receiving the authorization callback, and
 * exchanges the received authorization code for tokens.
 */
public final class TestApp implements AutoCloseable {

    private final HttpServer server;
    private final int port;
    private final AtomicInteger callbackCount = new AtomicInteger();
    private volatile URI lastCallbackUri;
    private volatile String lastCodeVerifier;

    TestApp() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.port = server.getAddress().getPort();
        server.createContext("/callback", this::handleCallback);
        server.start();
    }

    // The redirect URI of this application
    public String callbackUrl() {
        return "http://localhost:%d/callback".formatted(port);
    }

    // Creates a PKCE authorization request URL for this application
    public String authorizationRequestUrl(String authorizationEndpoint, String clientId) {
        String state = SecretGenerator.getInstance().randomString(16);
        String codeVerifier = PkceUtils.generateCodeVerifier();
        lastCodeVerifier = codeVerifier;
        String codeChallenge = PkceUtils.generateS256CodeChallenge(codeVerifier);

        return authorizationEndpoint + "?client_id=" + urlEncode(clientId)
                + "&redirect_uri=" + urlEncode(callbackUrl())
                + "&response_type=code"
                + "&scope=openid"
                + "&state=" + urlEncode(state)
                + "&code_challenge=" + urlEncode(codeChallenge)
                + "&code_challenge_method=S256";
    }

    // Exchanges the authorization code of the last received callback for tokens
    public HttpResponse<String> exchangeAuthorizationCode(String tokenEndpoint, String clientId) throws Exception {
        URI callbackUri = lastCallbackUri;
        if (callbackUri == null) {
            throw new IllegalStateException("No authorization callback received");
        }
        String codeVerifier = lastCodeVerifier;
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new IllegalStateException("No PKCE code verifier; create the authorization request via this app");
        }
        String code = queryParam(callbackUri, "code");

        String form = "grant_type=authorization_code"
                + "&client_id=" + urlEncode(clientId)
                + "&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(callbackUrl())
                + "&code_verifier=" + urlEncode(codeVerifier);

        return HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(tokenEndpoint))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .POST(HttpRequest.BodyPublishers.ofString(form))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    // Number of authorization callbacks received since the last reset
    public int callbackCount() {
        return callbackCount.get();
    }

    // The URI of the last received authorization callback, including the code
    public URI lastCallbackUri() {
        return lastCallbackUri;
    }

    public void reset() {
        callbackCount.set(0);
        lastCallbackUri = null;
        lastCodeVerifier = null;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handleCallback(HttpExchange exchange) throws IOException {
        callbackCount.incrementAndGet();
        lastCallbackUri = exchange.getRequestURI();

        String response = "<!doctype html><html><body><pre>OK</pre></body></html>";
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String queryParam(URI uri, String name) {
        String query = uri.getQuery() != null ? uri.getQuery() : "";
        for (String param : query.split("&")) {
            if (param.startsWith(name + "=")) {
                return URLDecoder.decode(param.substring(name.length() + 1), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalArgumentException("No query parameter named " + name + " found in " + uri);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
