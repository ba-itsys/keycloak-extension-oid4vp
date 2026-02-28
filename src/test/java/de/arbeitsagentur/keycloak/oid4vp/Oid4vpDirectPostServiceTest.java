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

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpDirectPostService.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

        Oid4vpAuthSessionResolver resolver = mock(Oid4vpAuthSessionResolver.class);
        Oid4vpRequestObjectStore store = mock(Oid4vpRequestObjectStore.class);

        service = new Oid4vpDirectPostService(session, realm, config, resolver, store);
    }

    @Test
    void handleCompletion_noEntry_returnsBadRequest() {
        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "token123")).thenReturn(null);

        Response response = service.handleCompletion("token123", null);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getEntity().toString()).contains("Session expired");
    }

    @Test
    void handleCompletion_missingRedirectUri_returnsServerError() {
        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "token123"))
                .thenReturn(Map.of("root_session_id", "root-1"));

        Response response = service.handleCompletion("token123", null);

        assertThat(response.getStatus()).isEqualTo(500);
    }

    @Test
    void handleCompletion_validEntry_redirects() {
        String redirectUri = "http://localhost:8080/realms/test/broker/oid4vp/endpoint/complete-auth?state=abc";
        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "token123"))
                .thenReturn(Map.of("redirect_uri", redirectUri));

        Response response = service.handleCompletion("token123", null);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getLocation().toString()).isEqualTo(redirectUri);
    }

    @Test
    void handleCompletion_walletSource_returnsHtml() {
        String redirectUri = "http://localhost:8080/realms/test/broker/oid4vp/endpoint/complete-auth?state=abc";
        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "token123"))
                .thenReturn(Map.of("redirect_uri", redirectUri));

        Response response = service.handleCompletion("token123", "wallet");

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getEntity().toString()).contains("Login Complete");
    }

    @Test
    void handleCompletion_openRedirectAttempt_returnsBadRequest() {
        when(singleUseObjects.get(CROSS_DEVICE_COMPLETE_PREFIX + "token123"))
                .thenReturn(Map.of("redirect_uri", "https://evil.example.com/steal"));

        Response response = service.handleCompletion("token123", null);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getEntity().toString()).contains("Invalid redirect URI");
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
        when(singleUseObjects.get(DEFERRED_AUTH_PREFIX + "missing-state")).thenReturn(null);

        Response response = service.completeAuth("missing-state", null, null);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getEntity().toString()).contains("Authentication data not found");
    }
}
