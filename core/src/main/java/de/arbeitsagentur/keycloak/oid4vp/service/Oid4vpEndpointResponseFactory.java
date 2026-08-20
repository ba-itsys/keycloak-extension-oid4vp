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

/** Builds the small JSON and redirect responses returned by the OID4VP endpoint. */
public class Oid4vpEndpointResponseFactory {

    public Response jsonRedirectResponse(String redirectUri) {
        try {
            String json = JsonSerialization.writeValueAsString(Map.of(OAuth2Constants.REDIRECT_URI, redirectUri));
            return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            return Response.ok("{\"redirect_uri\":\"\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    /**
     * Answers a wallet-reported error response with 200 and the error alongside the
     * {@code redirect_uri} the wallet must follow, as OID4VP 1.0 §8.2 permits for Error Responses.
     */
    public Response jsonErrorRedirectResponse(String error, String description, String redirectUri) {
        try {
            Map<String, String> body = new LinkedHashMap<>();
            body.put(OAuth2Constants.ERROR, error);
            if (description != null) {
                body.put(OAuth2Constants.ERROR_DESCRIPTION, description);
            }
            body.put(OAuth2Constants.REDIRECT_URI, redirectUri);
            return Response.ok(JsonSerialization.writeValueAsString(body))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            return jsonRedirectResponse(redirectUri);
        }
    }

    public Response jsonErrorResponse(Response.Status status, String error, String description) {
        try {
            Object body = description != null
                    ? Map.of(OAuth2Constants.ERROR, error, OAuth2Constants.ERROR_DESCRIPTION, description)
                    : Map.of(OAuth2Constants.ERROR, error);
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
