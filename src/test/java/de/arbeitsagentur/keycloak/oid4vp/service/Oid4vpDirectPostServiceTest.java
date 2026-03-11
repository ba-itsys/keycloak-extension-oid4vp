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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderDataMarshaller;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

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
        when(realm.getAccessCodeLifespanLogin()).thenReturn(600);
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

        Oid4vpRequestObjectStore store = mock(Oid4vpRequestObjectStore.class);

        service = new Oid4vpDirectPostService(session, realm, config, store);
    }

    @Test
    void buildCompleteAuthUrl_constructsCorrectUrl() {
        String url = service.buildCompleteAuthUrl("handle-1");

        assertThat(url)
                .isEqualTo(
                        "http://localhost:8080/realms/test-realm/broker/oid4vp/endpoint/complete-auth?request_handle=handle-1");
    }

    @Test
    void buildCompleteAuthUrl_encodesSpecialCharacters() {
        String url = service.buildCompleteAuthUrl("handle with spaces&special=chars");

        assertThat(url).contains("handle+with+spaces");
        assertThat(url).doesNotContain("&special=chars");
    }

    @Test
    void completeAuth_noSignal_returnsBadRequest() {
        when(singleUseObjects.remove(DEFERRED_AUTH_PREFIX + "missing-handle")).thenReturn(null);

        Response response = service.completeAuth("missing-handle", null, null);

        assertThat(response.getStatus()).isEqualTo(400);
        verify(singleUseObjects).remove(CROSS_DEVICE_COMPLETE_PREFIX + "missing-handle");
    }

    @Test
    void storeAndSignal_sameDevice_skipsCrossDeviceSseSignal() {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        Oid4vpIdentityProviderConfig idpConfig = new Oid4vpIdentityProviderConfig();
        idpConfig.setAlias("oid4vp");
        BrokeredIdentityContext context = createBrokeredIdentityContext(idpConfig);

        when(authSession.getParentSession()).thenReturn(rootSession);
        when(authSession.getRealm()).thenReturn(realm);
        when(rootSession.getId()).thenReturn("root-session");
        when(authSession.getTabId()).thenReturn("tab-1");
        when(realm.isRegistrationEmailAsUsername()).thenReturn(false);

        Response response = service.storeAndSignal(authSession, "handle-1", context, false);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(singleUseObjects).put(eq(DEFERRED_AUTH_PREFIX + "handle-1"), eq(600L), anyMap());
        verify(singleUseObjects, never()).put(eq(CROSS_DEVICE_COMPLETE_PREFIX + "handle-1"), anyLong(), anyMap());
    }

    @Test
    void storeAndSignal_crossDevice_storesSseSignal() {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
        Oid4vpIdentityProviderConfig idpConfig = new Oid4vpIdentityProviderConfig();
        idpConfig.setAlias("oid4vp");
        BrokeredIdentityContext context = createBrokeredIdentityContext(idpConfig);

        when(authSession.getParentSession()).thenReturn(rootSession);
        when(authSession.getRealm()).thenReturn(realm);
        when(rootSession.getId()).thenReturn("root-session");
        when(authSession.getTabId()).thenReturn("tab-1");
        when(realm.isRegistrationEmailAsUsername()).thenReturn(false);

        Response response = service.storeAndSignal(authSession, "handle-2", context, true);

        assertThat(response.getStatus()).isEqualTo(200);
        String completeAuthUrl = service.buildCompleteAuthUrl("handle-2");
        verify(singleUseObjects).put(eq(DEFERRED_AUTH_PREFIX + "handle-2"), eq(600L), anyMap());
        verify(singleUseObjects)
                .put(
                        eq(CROSS_DEVICE_COMPLETE_PREFIX + "handle-2"),
                        eq(300L),
                        eq(Map.of(KEY_COMPLETE_AUTH_URL, completeAuthUrl)));
    }

    @SuppressWarnings("unchecked")
    private BrokeredIdentityContext createBrokeredIdentityContext(Oid4vpIdentityProviderConfig idpConfig) {
        BrokeredIdentityContext context = new BrokeredIdentityContext("broker-user", idpConfig);
        UserAuthenticationIdentityProvider<Oid4vpIdentityProviderConfig> idp =
                mock(UserAuthenticationIdentityProvider.class);
        IdentityProviderDataMarshaller marshaller = new IdentityProviderDataMarshaller() {
            @Override
            public String serialize(Object object) {
                return object != null ? object.toString() : "";
            }

            @Override
            public <T> T deserialize(String value, Class<T> clazz) {
                return null;
            }
        };
        when(idp.getMarshaller()).thenReturn(marshaller);
        context.setIdp(idp);
        return context;
    }
}
