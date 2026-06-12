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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.util.Map;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/** Builds the small JSON and redirect responses returned by the OID4VP endpoint. */
public class Oid4vpEndpointResponseFactory {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpIdentityProviderConfig config;

    public Oid4vpEndpointResponseFactory(
            KeycloakSession session, RealmModel realm, Oid4vpIdentityProviderConfig config) {
        this.session = session;
        this.realm = realm;
        this.config = config;
    }

    public static Response jsonRedirectResponse(String redirectUri) {
        try {
            String json = JsonSerialization.writeValueAsString(Map.of(OAuth2Constants.REDIRECT_URI, redirectUri));
            return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            return Response.ok("{\"redirect_uri\":\"\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
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

    public String buildErrorRedirectUri(String error, String errorDescription, String state) {
        String base = Oid4vpConstants.buildEndpointBaseUrl(
                session.getContext().getUri().getBaseUri(), realm.getName(), config.getAlias());
        UriBuilder builder = UriBuilder.fromUri(base);
        if (state != null) {
            builder.queryParam(OAuth2Constants.STATE, state);
        }
        builder.queryParam(OAuth2Constants.ERROR, error);
        if (errorDescription != null) {
            builder.queryParam(OAuth2Constants.ERROR_DESCRIPTION, errorDescription);
        }
        return builder.build().toString();
    }
}
