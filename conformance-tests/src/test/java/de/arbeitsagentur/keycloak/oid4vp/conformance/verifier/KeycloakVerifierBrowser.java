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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.conformance.containers.OpenIdConformanceSuite;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ModuleRun;
import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.keycloak.common.util.Base64Url;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Plays the user's browser in the same-device flow: it requests the Keycloak login page, follows
 * the wallet link parameters into the conformance suite, and follows redirects back to Keycloak
 * sharing one cookie session. The suite and Keycloak advertise container-network hostnames that
 * are rewritten to their host-reachable counterparts.
 */
public final class KeycloakVerifierBrowser {

    public record AuthorizationRequest(String clientId, String requestUri, JsonNode requestObjectClaims) {}

    private static final Pattern WALLET_LINK = Pattern.compile("id=\"oid4vp-open-wallet\"[^>]*href=\"([^\"]+)\"");

    private final OpenIdConformanceSuite suite;
    private final String keycloakLocalBaseUrl;
    private final HttpClient httpClient;

    public KeycloakVerifierBrowser(OpenIdConformanceSuite suite, String keycloakLocalBaseUrl) {
        this.suite = suite;
        this.keycloakLocalBaseUrl = keycloakLocalBaseUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .sslContext(trustAllSslContext())
                .build();
    }

    // Requests the Keycloak login page and extracts the same-device authorization request
    public AuthorizationRequest fetchSameDeviceAuthorizationRequest(String realm, String clientId, String idpAlias) {
        String codeVerifier = PkceUtils.generateCodeVerifier();
        String loginUrl = keycloakLocalBaseUrl + "/realms/" + realm + "/protocol/openid-connect/auth"
                + "?client_id=" + urlEncode(clientId)
                + "&response_type=code"
                + "&scope=openid"
                + "&redirect_uri=" + urlEncode(OpenIdConformanceSuite.KEYCLOAK_BASE_URI + "/callback")
                + "&code_challenge=" + urlEncode(PkceUtils.generateS256CodeChallenge(codeVerifier))
                + "&code_challenge_method=S256"
                + "&kc_idp_hint=" + urlEncode(idpAlias);

        HttpResponse<String> response = getFollowingRedirects(URI.create(loginUrl));
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Keycloak login page returned HTTP " + response.statusCode() + ": " + response.body());
        }
        Matcher matcher = WALLET_LINK.matcher(response.body());
        if (!matcher.find()) {
            throw new IllegalStateException("Keycloak login page did not contain the same-device wallet link");
        }
        String walletUrl = matcher.group(1).replace("&amp;", "&");
        Map<String, String> parameters = queryParameters(walletUrl);
        String walletClientId = required(parameters, "client_id", walletUrl);
        String requestUri = required(parameters, "request_uri", walletUrl);
        return new AuthorizationRequest(walletClientId, requestUri, fetchRequestObjectClaims(requestUri));
    }

    // Hands the authorization request to the suite's wallet and follows redirects back to Keycloak
    public void triggerAuthorization(ModuleRun moduleRun, AuthorizationRequest request) {
        URI authorizationEndpoint = suite.externalUri(moduleRun.authorizationEndpoint());
        String url = authorizationEndpoint
                + (authorizationEndpoint.getQuery() != null ? "&" : "?")
                + "client_id=" + urlEncode(request.clientId())
                + "&request_uri=" + urlEncode(request.requestUri());

        getFollowingRedirects(URI.create(url));
    }

    private JsonNode fetchRequestObjectClaims(String requestUri) {
        HttpResponse<String> response = get(toLocalKeycloakUri(URI.create(requestUri)));
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Request object fetch returned HTTP " + response.statusCode() + ": " + response.body());
        }
        String[] parts = response.body().trim().split("\\.");
        if (parts.length != 3) {
            throw new IllegalStateException("Request object is not a compact JWT: " + response.body());
        }
        return JsonSerialization.valueFromString(
                new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8), JsonNode.class);
    }

    private HttpResponse<String> get(URI uri) {
        try {
            return httpClient.send(
                    HttpRequest.newBuilder(uri)
                            .timeout(Duration.ofMinutes(1))
                            .header(
                                    "Accept",
                                    "text/html,application/json,application/oauth-authz-req+jwt,application/jwt,text/plain")
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new RuntimeException("Request failed: " + uri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while requesting " + uri, e);
        }
    }

    private HttpResponse<String> getFollowingRedirects(URI uri) {
        URI current = uri;
        for (int redirects = 0; redirects < 10; redirects++) {
            URI requested = current;
            HttpResponse<String> response = get(requested);
            if (response.statusCode() >= 400) {
                throw new IllegalStateException("Authorization flow returned HTTP " + response.statusCode() + " for "
                        + requested + ": " + response.body());
            }
            if (response.statusCode() < 300) {
                return response;
            }
            URI next = requested.resolve(response.headers()
                    .firstValue("Location")
                    .orElseThrow(
                            () -> new IllegalStateException("Redirect without Location header from " + requested)));
            // A redirect to the suite's results page means the wallet interaction is complete. The
            // module verdict is then read from the suite's module status, not the browser response
            if (next.getPath() != null && next.getPath().contains("log-detail")) {
                return response;
            }
            current = rewriteToHostReachable(next);
        }
        throw new IllegalStateException("Too many redirects, last URL: " + current);
    }

    // Rewrites container-network hostnames to their host-reachable counterparts
    private URI rewriteToHostReachable(URI uri) {
        if (OpenIdConformanceSuite.KEYCLOAK_BASE_URI.getHost().equals(uri.getHost())) {
            return toLocalKeycloakUri(uri);
        }
        return suite.externalUri(uri);
    }

    private URI toLocalKeycloakUri(URI uri) {
        return URI.create(
                keycloakLocalBaseUrl + uri.getRawPath() + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : ""));
    }

    private static Map<String, String> queryParameters(String url) {
        Map<String, String> parameters = new HashMap<>();
        String query = url.contains("?") ? url.substring(url.indexOf('?') + 1) : "";
        for (String parameter : query.split("&")) {
            int separator = parameter.indexOf('=');
            if (separator > 0) {
                parameters.put(
                        URLDecoder.decode(parameter.substring(0, separator), StandardCharsets.UTF_8),
                        URLDecoder.decode(parameter.substring(separator + 1), StandardCharsets.UTF_8));
            }
        }
        return parameters;
    }

    private static String required(Map<String, String> parameters, String name, String url) {
        String value = parameters.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Wallet link did not contain " + name + ": " + url);
        }
        return value;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static SSLContext trustAllSslContext() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(
                    null,
                    new TrustManager[] {
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }
                        }
                    },
                    new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create trust-all SSL context", e);
        }
    }
}
