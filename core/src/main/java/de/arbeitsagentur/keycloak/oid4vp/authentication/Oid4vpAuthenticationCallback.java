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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.AuthenticationCallback;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Returns a presentation that an authenticator or required action started to that execution, and
 * hands every other one to Keycloak's broker as a login.
 */
public final class Oid4vpAuthenticationCallback implements AuthenticationCallback {

    private static final Logger LOG = Logger.getLogger(Oid4vpAuthenticationCallback.class);

    private final KeycloakSession session;
    private final UserAuthenticationIdentityProvider<?> provider;
    private final IdentityProviderModel model;
    private final AuthenticationCallback broker;

    public Oid4vpAuthenticationCallback(
            KeycloakSession session,
            UserAuthenticationIdentityProvider<?> provider,
            IdentityProviderModel model,
            AuthenticationCallback broker) {
        this.session = session;
        this.provider = provider;
        this.model = model;
        this.broker = broker;
    }

    @Override
    public Response authenticated(BrokeredIdentityContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (Oid4vpPresentationSession.isPending(authSession, model.getAlias())) {
            preprocess(context);
            return Oid4vpPresentationSession.complete(authSession, context);
        }
        if (context.getContextData().containsKey(Oid4vpMapperUtils.CONTEXT_PRESENTATION_ONLY_KEY)) {
            LOG.warnf("OID4VP IdP '%s' has no principalAttributes and refuses the login", model.getAlias());
            return broker.error(model, Oid4vpMessages.PRESENTATION_ONLY);
        }
        return broker.authenticated(context);
    }

    @Override
    public Response cancelled(IdentityProviderModel idpConfig) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (Oid4vpPresentationSession.isPending(authSession, model.getAlias())) {
            return Oid4vpPresentationSession.fail(authSession, Oid4vpMessages.PRESENTATION_CANCELLED);
        }
        return broker.cancelled(idpConfig);
    }

    @Override
    public Response error(IdentityProviderModel idpConfig, String message) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (Oid4vpPresentationSession.isPending(authSession, model.getAlias())) {
            return Oid4vpPresentationSession.fail(authSession, message);
        }
        return broker.error(idpConfig, message);
    }

    @Override
    public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {
        return broker.getAndVerifyAuthenticationSession(encodedCode);
    }

    @Override
    public Response retryLogin(
            UserAuthenticationIdentityProvider<?> identityProvider, AuthenticationSessionModel authSession) {
        return broker.retryLogin(identityProvider, authSession);
    }

    // Mirrors the preprocessing the broker runs before it looks for the user.
    private void preprocess(BrokeredIdentityContext context) {
        RealmModel realm = session.getContext().getRealm();
        provider.preprocessFederatedIdentity(session, realm, context);
        session.identityProviders().getMappersByAliasStream(model.getAlias()).forEach(mapper -> {
            IdentityProviderMapper target = (IdentityProviderMapper) session.getKeycloakSessionFactory()
                    .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            if (target != null) {
                target.preprocessFederatedIdentity(session, realm, mapper, context);
            }
        });
    }
}
