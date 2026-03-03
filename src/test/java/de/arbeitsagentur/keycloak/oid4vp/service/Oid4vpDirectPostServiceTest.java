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

import static de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpAuthSessionResolver;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;

class Oid4vpDirectPostServiceTest {

    private Oid4vpDirectPostService service;
    private KeycloakSession session;
    private SingleUseObjectProvider singleUseObjects;
    private RealmModel realm;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        singleUseObjects = mock(SingleUseObjectProvider.class);
        Oid4vpIdentityProviderConfig config = mock(Oid4vpIdentityProviderConfig.class);

        when(session.singleUseObjects()).thenReturn(singleUseObjects);
        when(realm.getName()).thenReturn("test-realm");
        when(config.getAlias()).thenReturn("oid4vp");
        when(config.getCrossDeviceCompleteTtlSeconds()).thenReturn(300);

        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));

        LoginFormsProvider loginFormsProvider = mock(LoginFormsProvider.class, RETURNS_SELF);
        when(session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createErrorPage(any(Response.Status.class))).thenAnswer(invocation -> {
            Response.Status status = invocation.getArgument(0);
            return Response.status(status).entity("error-page").build();
        });

        Oid4vpAuthSessionResolver resolver = mock(Oid4vpAuthSessionResolver.class);
        Oid4vpRequestObjectStore store = mock(Oid4vpRequestObjectStore.class);

        service = new Oid4vpDirectPostService(session, realm, config, resolver, store);
    }

    @Test
    void buildCompleteAuthUrl_constructsCorrectUrl() {
        String url = service.buildCompleteAuthUrl("test-state");

        assertThat(url)
                .isEqualTo(
                        "http://localhost:8080/realms/test-realm/broker/oid4vp/endpoint/complete-auth?state=test-state");
    }

    @Test
    void buildCompleteAuthUrl_encodesSpecialCharacters() {
        String url = service.buildCompleteAuthUrl("state with spaces&special=chars");

        assertThat(url).contains("state+with+spaces");
        assertThat(url).doesNotContain("&special=chars");
    }

    @Test
    void completeAuth_noSignal_returnsBadRequest() {
        when(singleUseObjects.remove(DEFERRED_AUTH_PREFIX + "missing-state")).thenReturn(null);

        Response response = service.completeAuth("missing-state", null, null);

        assertThat(response.getStatus()).isEqualTo(400);
    }
}
