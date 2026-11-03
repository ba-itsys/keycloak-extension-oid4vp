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
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.util.AuthenticationFlowURLHelper;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Asks for an OID4VP presentation with the identity provider named in the authenticator
 * configuration and identifies the user through the identity provider link, the link a login
 * through that identity provider uses. A presentation to an identity provider without principal
 * attributes identifies nobody, so only its claims are kept.
 */
public class Oid4vpPresentationAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String execution = context.getExecution().getId();
        Optional<String> failure = Oid4vpPresentationSession.failure(authSession, execution);
        if (failure.isPresent()) {
            Oid4vpPresentationSession.clear(authSession);
            context.failureChallenge(
                    AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, errorPage(context, failure.get()));
            return;
        }
        Optional<Oid4vpPresentation> presentation = Oid4vpPresentationSession.result(authSession)
                .filter(result -> result.execution().equals(execution));
        if (presentation.isEmpty()) {
            context.challenge(Oid4vpPresentationSession.start(
                    context.getSession(),
                    authSession,
                    identityProviderAlias(context.getAuthenticatorConfig()),
                    execution,
                    returnUrl(context)));
            return;
        }
        String alias = presentation.get().identityProviderAlias();
        Optional<String> refusal = verify(context, presentation.get());
        if (refusal.isEmpty()) {
            refusal = identify(context, presentation.get());
        }
        if (refusal.isPresent()) {
            Oid4vpPresentationSession.clear(authSession);
            context.getEvent().clone().detail(Details.IDENTITY_PROVIDER, alias).error(refusal.get());
            context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED, errorPage(context, refusal.get()));
            return;
        }
        context.getEvent().detail(Details.IDENTITY_PROVIDER, alias);
        context.success();
    }

    /**
     * Decides whether the verified presentation completes the execution, for example by comparing a
     * claim with the user. Returns the message key of a refusal, or empty.
     */
    protected Optional<String> verify(AuthenticationFlowContext context, Oid4vpPresentation presentation) {
        return Optional.empty();
    }

    /**
     * Sets the linked user when the flow has none, and otherwise requires the link to point to the
     * user of the flow. It never links, because a username form alone identifies a user without
     * authenticating them. Returns the message key of a refusal, or empty.
     */
    protected Optional<String> identify(AuthenticationFlowContext context, Oid4vpPresentation presentation) {
        if (presentation.identityKey() == null) {
            return presentation.subjectCredentialMissing()
                    ? Optional.of(Oid4vpMessages.PRESENTATION_NOT_LINKED)
                    : Optional.empty();
        }
        UserModel linked =
                identityLinks(context.getSession(), context.getRealm()).linkedUser(presentation);
        if (linked == null) {
            return Optional.of(Oid4vpMessages.PRESENTATION_NOT_LINKED);
        }
        UserModel user = context.getUser();
        if (user == null) {
            context.setUser(linked);
            return Optional.empty();
        }
        return user.getId().equals(linked.getId())
                ? Optional.empty()
                : Optional.of(Oid4vpMessages.PRESENTATION_OTHER_USER);
    }

    protected Oid4vpIdentityLinks identityLinks(KeycloakSession session, RealmModel realm) {
        return new Oid4vpIdentityLinks(session, realm);
    }

    private static URI returnUrl(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        return new AuthenticationFlowURLHelper(context.getSession(), context.getRealm(), context.getUriInfo())
                .getLastExecutionUrl(
                        context.getFlowPath(),
                        context.getExecution().getId(),
                        authSession.getClient().getClientId(),
                        authSession.getTabId(),
                        AuthenticationProcessor.getClientData(context.getSession(), authSession));
    }

    private static Response errorPage(AuthenticationFlowContext context, String messageKey) {
        return context.form().setError(messageKey).createErrorPage(Response.Status.FORBIDDEN);
    }

    private static String identityProviderAlias(AuthenticatorConfigModel config) {
        return Oid4vpPresentationAuthenticatorFactory.identityProviderAlias(
                config == null ? Map.of() : config.getConfig());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
