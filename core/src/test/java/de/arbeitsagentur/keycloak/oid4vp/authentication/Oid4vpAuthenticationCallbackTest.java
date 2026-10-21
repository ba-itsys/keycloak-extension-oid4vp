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
package de.arbeitsagentur.keycloak.oid4vp.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.AuthenticationCallback;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.sessions.AuthenticationSessionModel;

// KeycloakOid4vpPresentationE2eIT covers the returns to a waiting execution.
class Oid4vpAuthenticationCallbackTest {

    private final RecordingBroker broker = new RecordingBroker();
    private final BrokeredIdentityContext context = Oid4vpPresentationSessionTest.presentedPid();
    private final Oid4vpAuthenticationCallback callback =
            new Oid4vpAuthenticationCallback(null, null, context.getIdpConfig(), broker);

    Oid4vpAuthenticationCallbackTest() {
        context.setAuthenticationSession(new InMemoryAuthenticationSession());
    }

    @Test
    void handsAPresentationNoExecutionWaitsForToTheBroker() {
        callback.authenticated(context);

        assertThat(broker.calls).containsExactly("authenticated");
    }

    @Test
    void refusesTheLoginOfAnIdentityProviderWithoutPrincipalAttributes() {
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_ONLY_KEY, "true");

        callback.authenticated(context);

        assertThat(broker.calls).containsExactly("error:" + Oid4vpMessages.PRESENTATION_ONLY);
    }

    private static final class RecordingBroker implements AuthenticationCallback {
        private final List<String> calls = new ArrayList<>();

        @Override
        public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Response authenticated(BrokeredIdentityContext context) {
            calls.add("authenticated");
            return Response.ok().build();
        }

        @Override
        public Response cancelled(IdentityProviderModel idpConfig) {
            calls.add("cancelled");
            return Response.ok().build();
        }

        @Override
        public Response retryLogin(
                UserAuthenticationIdentityProvider<?> identityProvider, AuthenticationSessionModel authSession) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Response error(IdentityProviderModel idpConfig, String message) {
            calls.add("error:" + message);
            return Response.ok().build();
        }
    }
}
