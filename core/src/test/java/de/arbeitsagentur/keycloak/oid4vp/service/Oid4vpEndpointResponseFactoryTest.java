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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/** The shapes the response URI answers a wallet with. */
class Oid4vpEndpointResponseFactoryTest {

    private static final String REDIRECT_URI = "https://verifier.example/failed?state=s1&response_code=rc1";

    private final Oid4vpEndpointResponseFactory factory = new Oid4vpEndpointResponseFactory();

    /** §8.2 defines {@code redirect_uri} as the single parameter of this response. */
    @Test
    void redirectResponseIsHttp200CarryingOnlyTheRedirectUri() throws IOException {
        Response response = factory.jsonRedirectResponse(REDIRECT_URI, false);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
        JsonNode body = body(response);
        assertThat(body.fieldNames()).toIterable().containsExactly("redirect_uri");
        assertThat(body.get("redirect_uri").asText()).isEqualTo(REDIRECT_URI);
    }

    /** A cross-device wallet is on the wrong device to be redirected, so it gets no URL. */
    @Test
    void crossDeviceRedirectResponseIsHttp200CarryingAnEmptyObject() throws IOException {
        Response response = factory.jsonRedirectResponse(REDIRECT_URI, true);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
        assertThat(response.getEntity()).isEqualTo("{}");
    }

    /**
     * With the rejection reported to the wallet, the error travels beside the redirect the End-User
     * follows, which §8.2 permits for Error Responses.
     */
    @Test
    void errorRedirectResponseIsHttp400CarryingTheErrorAndTheRedirectUri() throws IOException {
        Response response = factory.jsonErrorRedirectResponse(
                "invalid_presentation", "Credential has been revoked", REDIRECT_URI, false);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
        JsonNode body = body(response);
        assertThat(body.fieldNames()).toIterable().containsExactly("error", "error_description", "redirect_uri");
        assertThat(body.get("redirect_uri").asText()).isEqualTo(REDIRECT_URI);
    }

    /** The browser of a cross-device flow is on another device, so no redirect is handed out. */
    @Test
    void crossDeviceErrorRedirectResponseCarriesNoRedirectUri() throws IOException {
        Response response = factory.jsonErrorRedirectResponse(
                "invalid_presentation", "Credential has been revoked", REDIRECT_URI, true);

        assertThat(response.getStatus()).isEqualTo(400);
        JsonNode body = body(response);
        assertThat(body.fieldNames()).toIterable().containsExactly("error", "error_description");
    }

    /** An IdentityBrokerException without a message leaves the description out. */
    @Test
    void errorRedirectResponseOmitsAnAbsentDescription() throws IOException {
        Response response = factory.jsonErrorRedirectResponse("invalid_presentation", null, REDIRECT_URI, false);

        assertThat(body(response).fieldNames()).toIterable().containsExactly("error", "redirect_uri");
    }

    /** A post that cannot be tied to a live login gets the caller's status and no redirect. */
    @Test
    void plainErrorResponseKeepsTheCallersStatusAndCarriesNoRedirect() throws IOException {
        Response badRequest =
                factory.jsonErrorResponse(Response.Status.BAD_REQUEST, "session_expired", "The login has expired");

        assertThat(badRequest.getStatus()).isEqualTo(400);
        assertThat(badRequest.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
        JsonNode body = body(badRequest);
        assertThat(body.get("error").asText()).isEqualTo("session_expired");
        assertThat(body.get("error_description").asText()).isEqualTo("The login has expired");
        assertThat(body.has("redirect_uri")).isFalse();

        Response serverError = factory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);

        assertThat(serverError.getStatus()).isEqualTo(500);
        assertThat(body(serverError).fieldNames()).toIterable().containsExactly("error");
    }

    private static JsonNode body(Response response) throws IOException {
        return JsonSerialization.readValue(String.valueOf(response.getEntity()), JsonNode.class);
    }
}
