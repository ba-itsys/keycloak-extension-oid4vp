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

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Models the wallet-facing OID4VP authorization request parameters carried by the same-device link.
 */
record Oid4vpAuthorizationRequestParameters(String clientId, URI requestUri) {

    static Oid4vpAuthorizationRequestParameters parse(String walletUrl) {
        URI uri = URI.create(walletUrl);
        Map<String, String> queryParams = parseQuery(uri.getRawQuery());
        String clientId = queryParams.get("client_id");
        String requestUri = queryParams.get("request_uri");
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("Missing client_id in wallet URL");
        }
        if (requestUri == null || requestUri.isBlank()) {
            throw new IllegalArgumentException("Missing request_uri in wallet URL");
        }
        return new Oid4vpAuthorizationRequestParameters(clientId, URI.create(requestUri));
    }

    URI toAuthorizationEndpoint(URI authorizationEndpoint) {
        String separator = authorizationEndpoint.getRawQuery() == null ? "?" : "&";
        return URI.create(authorizationEndpoint + separator + "client_id=" + encode(clientId) + "&request_uri="
                + encode(requestUri.toString()));
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            int separator = pair.indexOf('=');
            if (separator < 0) {
                params.put(decode(pair), "");
                continue;
            }
            params.put(decode(pair.substring(0, separator)), decode(pair.substring(separator + 1)));
        }
        return params;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
