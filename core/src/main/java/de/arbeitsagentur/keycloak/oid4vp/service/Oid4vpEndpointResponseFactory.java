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
package de.arbeitsagentur.keycloak.oid4vp.service;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.OAuth2Constants;
import org.keycloak.util.JsonSerialization;

public class Oid4vpEndpointResponseFactory {

    /**
     * Returns HTTP 200 with the {@code redirect_uri} the wallet must follow, or an empty object in a
     * cross-device flow, where the browser is moved over the SSE stream instead. §8.2 makes
     * {@code redirect_uri} optional, so a wallet served none stops there.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2, Response Mode direct_post</a>
     */
    public Response jsonRedirectResponse(String redirectUri, boolean isCrossDevice) {
        if (isCrossDevice) {
            return json(Response.Status.OK, Map.of());
        }
        return json(Response.Status.OK, Map.of(OAuth2Constants.REDIRECT_URI, redirectUri));
    }

    /**
     * Returns HTTP 400 with the error beside the {@code redirect_uri} that hands the End-User back,
     * which §8.2 permits for Error Responses.
     */
    public Response jsonErrorRedirectResponse(
            String error, String description, String redirectUri, boolean isCrossDevice) {
        if (isCrossDevice) {
            return jsonErrorResponse(Response.Status.BAD_REQUEST, error, description);
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put(OAuth2Constants.ERROR, error);
        if (description != null) {
            body.put(OAuth2Constants.ERROR_DESCRIPTION, description);
        }
        body.put(OAuth2Constants.REDIRECT_URI, redirectUri);
        return json(Response.Status.BAD_REQUEST, body);
    }

    public Response jsonErrorResponse(Response.Status status, String error, String description) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put(OAuth2Constants.ERROR, error);
        if (description != null) {
            body.put(OAuth2Constants.ERROR_DESCRIPTION, description);
        }
        return json(status, body);
    }

    private Response json(Response.Status status, Map<String, String> body) {
        try {
            return Response.status(status)
                    .entity(JsonSerialization.writeValueAsString(body))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            return Response.status(status)
                    .entity("{\"error\":\"server_error\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
