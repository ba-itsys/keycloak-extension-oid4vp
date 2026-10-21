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

import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpIdentityKey;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Asks an authenticated user for an OID4VP presentation with the identity provider named in the
 * required action configuration, also as application initiated action
 * ({@code kc_action=oid4vp-presentation}), and links its identity to the user. Subclasses decide in
 * {@link #verify} whether a verified presentation completes the action.
 */
public class Oid4vpPresentationRequiredAction implements RequiredActionProvider {

    public static final String PROVIDER_ID = "oid4vp-presentation";

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {}

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String execution = context.getAction();
        Optional<String> failure = Oid4vpPresentationSession.failure(authSession, execution);
        if (failure.isPresent()) {
            Oid4vpPresentationSession.clear(authSession);
            context.challenge(errorPage(context, failure.get()));
            return;
        }
        Optional<Oid4vpPresentation> presentation = Oid4vpPresentationSession.result(authSession)
                .filter(result -> result.execution().equals(execution));
        if (presentation.isEmpty()) {
            context.challenge(Oid4vpPresentationSession.start(
                    context.getSession(), authSession, identityProviderAlias(context), execution, returnUrl(context)));
            return;
        }
        String alias = presentation.get().identityProviderAlias();
        Optional<String> refusal = verify(context, presentation.get());
        if (refusal.isEmpty()) {
            refusal = link(context, presentation.get());
        }
        if (refusal.isPresent()) {
            Oid4vpPresentationSession.clear(authSession);
            context.getEvent().clone().detail(Details.IDENTITY_PROVIDER, alias).error(refusal.get());
            context.challenge(errorPage(context, refusal.get()));
            return;
        }
        context.getEvent().detail(Details.IDENTITY_PROVIDER, alias);
        context.success();
    }

    @Override
    public void processAction(RequiredActionContext context) {
        requiredActionChallenge(context);
    }

    /**
     * Decides whether the verified presentation completes the action. Returns the message key that
     * refuses it, or empty to accept it. The default accepts every verified presentation.
     */
    protected Optional<String> verify(RequiredActionContext context, Oid4vpPresentation presentation) {
        return Optional.empty();
    }

    /**
     * Links the identity of the presentation to the user, who is authenticated at this point. A
     * presentation without the subject credential gets a subject derived from the user, and the
     * configured subject credential carrying it is offered. Returns the message key that refuses the
     * presentation, or empty to accept it.
     */
    protected Optional<String> link(RequiredActionContext context, Oid4vpPresentation presentation) {
        UserModel user = context.getUser();
        Oid4vpIdentityLinks links = identityLinks(context.getSession(), context.getRealm());
        String alias = presentation.identityProviderAlias();
        if (presentation.subjectCredentialMissing()) {
            String subject = ReferenceCredentialBinding.of(context.getSession(), context.getRealm())
                    .subjectOf(user.getId());
            links.link(user, alias, Oid4vpIdentityKey.caseInsensitive(subject));
            Oid4vpSubjectCredentialOffer.offer(
                    context.getSession(),
                    context.getRealm(),
                    context.getAuthenticationSession(),
                    user,
                    presentation.credentials(),
                    subject,
                    config(context));
            return Optional.empty();
        }
        if (presentation.identityKey() == null) {
            return Optional.empty();
        }
        UserModel linked = links.linkedUser(presentation);
        if (linked == null) {
            links.link(user, alias, presentation.identityKey());
            return Optional.empty();
        }
        return linked.getId().equals(user.getId())
                ? Optional.empty()
                : Optional.of(Oid4vpMessages.PRESENTATION_OTHER_USER);
    }

    protected Oid4vpIdentityLinks identityLinks(KeycloakSession session, RealmModel realm) {
        return new Oid4vpIdentityLinks(session, realm);
    }

    protected String identityProviderAlias(RequiredActionContext context) {
        return Oid4vpPresentationAuthenticatorFactory.identityProviderAlias(config(context));
    }

    private static Map<String, String> config(RequiredActionContext context) {
        RequiredActionConfigModel config = context.getConfig();
        return config == null ? Map.of() : config.getConfig();
    }

    // Resumes this required action with a GET without session code, as Keycloak's broker does.
    protected URI returnUrl(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        return LoginActionsService.loginActionsBaseUrl(context.getUriInfo())
                .path(LoginActionsService.REQUIRED_ACTION)
                .queryParam(Constants.EXECUTION, context.getAction())
                .queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId())
                .queryParam(Constants.TAB_ID, authSession.getTabId())
                .queryParam(
                        Constants.CLIENT_DATA, AuthenticationProcessor.getClientData(context.getSession(), authSession))
                .build(context.getRealm().getName());
    }

    private static Response errorPage(RequiredActionContext context, String messageKey) {
        return context.form().setError(messageKey).createErrorPage(Response.Status.FORBIDDEN);
    }

    @Override
    public void close() {}
}
