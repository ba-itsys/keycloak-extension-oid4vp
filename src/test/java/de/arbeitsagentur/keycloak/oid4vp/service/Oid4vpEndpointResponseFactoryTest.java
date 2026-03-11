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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;

class Oid4vpEndpointResponseFactoryTest {

    private Oid4vpEndpointResponseFactory responseFactory;

    @BeforeEach
    void setUp() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");

        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(realm.getName()).thenReturn("test-realm");

        responseFactory = new Oid4vpEndpointResponseFactory(session, realm, config);
    }

    @Test
    void jsonErrorResponse_doesNotLeakDescriptionWhenNull() {
        Response response =
                responseFactory.jsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);

        assertThat((String) response.getEntity()).contains("server_error").doesNotContain("error_description");
    }

    @Test
    void jsonErrorResponse_includesDescriptionWhenProvided() {
        Response response =
                responseFactory.jsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state");

        assertThat((String) response.getEntity()).contains("Missing state");
    }

    @Test
    void buildErrorRedirectUri_includesStateAndErrorDetails() {
        String redirectUri = responseFactory.buildErrorRedirectUri("access_denied", "Wallet rejected", "state-1");

        assertThat(redirectUri)
                .contains("state=state-1")
                .contains("error=access_denied")
                .contains("error_description=Wallet+rejected");
    }
}
