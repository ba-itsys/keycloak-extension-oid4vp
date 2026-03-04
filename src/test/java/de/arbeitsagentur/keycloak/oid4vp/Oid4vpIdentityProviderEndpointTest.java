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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Method;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;

class Oid4vpIdentityProviderEndpointTest {

    private Oid4vpIdentityProviderEndpoint endpoint;

    @BeforeEach
    void setUp() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");

        Oid4vpIdentityProvider provider = mock(Oid4vpIdentityProvider.class);
        Oid4vpIdentityProviderConfig config = mock(Oid4vpIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.getSsePollIntervalMs()).thenReturn(2000);
        when(config.getSseTimeoutSeconds()).thenReturn(120);
        when(config.getSsePingIntervalSeconds()).thenReturn(10);
        when(config.getCrossDeviceCompleteTtlSeconds()).thenReturn(300);
        when(provider.getConfig()).thenReturn(config);

        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(uriInfo.getRequestUri())
                .thenReturn(URI.create("http://localhost:8080/realms/test/broker/oid4vp/endpoint"));
        when(context.getUri()).thenReturn(uriInfo);
        when(session.getContext()).thenReturn(context);

        AbstractIdentityProvider.AuthenticationCallback callback =
                mock(AbstractIdentityProvider.AuthenticationCallback.class);
        EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);

        Oid4vpRequestObjectStore store = mock(Oid4vpRequestObjectStore.class);

        endpoint = new Oid4vpIdentityProviderEndpoint(session, realm, provider, callback, event, store);
    }

    @Test
    void handlePost_withNoSessionMatch_returnsSessionExpiredError() {
        Response response = endpoint.handlePost(null, null, null, null, null, null, null);
        assertThat(response.getStatus()).isEqualTo(400);
        String body = (String) response.getEntity();
        assertThat(body).contains("session_expired");
    }

    @Test
    void jsonErrorResponse_doesNotLeakDescription_whenNull() {
        Response response = invokeJsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        String body = (String) response.getEntity();
        assertThat(body).contains("server_error");
        assertThat(body).doesNotContain("error_description");
    }

    @Test
    void jsonErrorResponse_includesDescription_whenProvided() {
        Response response = invokeJsonErrorResponse(Response.Status.BAD_REQUEST, "invalid_request", "Missing state");
        String body = (String) response.getEntity();
        assertThat(body).contains("Missing state");
    }

    @Test
    void jsonErrorResponse_serverError_doesNotIncludeInternalDetails() {
        // Simulate what would happen if e.getMessage() were passed — it shouldn't be
        Response response = invokeJsonErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "server_error", null);
        String body = (String) response.getEntity();
        assertThat(body).doesNotContain("NullPointerException");
        assertThat(body).doesNotContain("stacktrace");
        assertThat(body).doesNotContain("java.");
    }

    private Response invokeJsonErrorResponse(Response.Status status, String error, String description) {
        try {
            Method method = Oid4vpIdentityProviderEndpoint.class.getDeclaredMethod(
                    "jsonErrorResponse", Response.Status.class, String.class, String.class);
            method.setAccessible(true);
            return (Response) method.invoke(endpoint, status, error, description);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
