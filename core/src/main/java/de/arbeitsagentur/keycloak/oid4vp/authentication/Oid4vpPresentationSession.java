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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * Runs an OID4VP presentation for an authenticator or required action with an existing OID4VP
 * identity provider, and keeps its outcome in the authentication session.
 *
 * <p>The identity provider's mappers define the DCQL query, and its verifier settings, trust
 * material and wallet page serve the presentation. The verified presentation logs nobody in and
 * links nothing. The mappers preprocess it, so their session notes reach the authentication
 * session, and the browser returns to the execution that started it.
 */
public final class Oid4vpPresentationSession {

    private static final Logger LOG = Logger.getLogger(Oid4vpPresentationSession.class);

    static final String ALIAS_NOTE = "oid4vp.presentation.alias";
    static final String EXECUTION_NOTE = "oid4vp.presentation.execution";
    static final String RETURN_URL_NOTE = "oid4vp.presentation.return_url";
    static final String RESULT_NOTE = "oid4vp.presentation.result";
    static final String FAILURE_NOTE = "oid4vp.presentation.failure";

    private Oid4vpPresentationSession() {}

    /**
     * Starts a presentation and returns the identity provider's wallet page as challenge. A new
     * presentation replaces the outcome of the previous one.
     *
     * @param execution the authenticator execution id or required action alias that asks
     * @param returnUrl the GET URL that resumes that execution
     */
    public static Response start(
            KeycloakSession session,
            AuthenticationSessionModel authSession,
            String identityProviderAlias,
            String execution,
            URI returnUrl) {
        IdentityProviderModel model = session.identityProviders().getByAlias(identityProviderAlias);
        if (model == null || !model.isEnabled() || !Oid4vpConstants.PROVIDER_ID.equals(model.getProviderId())) {
            throw new IllegalStateException(
                    "'" + identityProviderAlias + "' is no enabled OID4VP identity provider of the realm");
        }
        authSession.removeAuthNote(RESULT_NOTE);
        authSession.removeAuthNote(FAILURE_NOTE);
        authSession.setAuthNote(ALIAS_NOTE, identityProviderAlias);
        authSession.setAuthNote(EXECUTION_NOTE, execution);
        authSession.setAuthNote(RETURN_URL_NOTE, returnUrl.toString());

        UserAuthenticationIdentityProvider<?> provider =
                IdentityBrokerService.getIdentityProvider(session, identityProviderAlias);
        return provider.performLogin(new AuthenticationRequest(
                session,
                session.getContext().getRealm(),
                authSession,
                session.getContext().getHttpRequest(),
                session.getContext().getUri(),
                null,
                returnUrl.toString()));
    }

    public static Optional<Oid4vpPresentation> result(AuthenticationSessionModel authSession) {
        String json = authSession.getAuthNote(RESULT_NOTE);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(json, Oid4vpPresentation.class));
        } catch (IOException e) {
            LOG.warnf("Discarding an unreadable OID4VP presentation: %s", e.getMessage());
            authSession.removeAuthNote(RESULT_NOTE);
            return Optional.empty();
        }
    }

    public static Optional<String> failure(AuthenticationSessionModel authSession, String execution) {
        if (!execution.equals(authSession.getAuthNote(EXECUTION_NOTE))) {
            return Optional.empty();
        }
        return Optional.ofNullable(authSession.getAuthNote(FAILURE_NOTE));
    }

    // Forgets the presentation, so the next challenge starts a new one.
    public static void clear(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(RESULT_NOTE);
        authSession.removeAuthNote(FAILURE_NOTE);
        authSession.removeAuthNote(ALIAS_NOTE);
        authSession.removeAuthNote(EXECUTION_NOTE);
        authSession.removeAuthNote(RETURN_URL_NOTE);
    }

    // The alias note stays set only while an execution waits for a presentation to the identity provider.
    public static boolean isPending(AuthenticationSessionModel authSession, String identityProviderAlias) {
        return authSession != null && identityProviderAlias.equals(authSession.getAuthNote(ALIAS_NOTE));
    }

    static Response complete(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        Map<String, Object> contextData = context.getContextData();
        boolean subjectCredentialMissing = contextData.containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
        boolean identifiesNobody = subjectCredentialMissing
                || contextData.containsKey(Oid4vpMapperUtils.CONTEXT_PRESENTATION_ONLY_KEY)
                || new Oid4vpIdentityProviderConfig(context.getIdpConfig()).isTransientUsersEnabled();
        Oid4vpPresentation presentation = new Oid4vpPresentation(
                authSession.getAuthNote(ALIAS_NOTE),
                authSession.getAuthNote(EXECUTION_NOTE),
                identifiesNobody ? null : context.getId(),
                subjectCredentialMissing,
                Oid4vpMapperUtils.presentedCredentials(context),
                (String) contextData.get(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY),
                (String) contextData.get(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY));
        try {
            authSession.setAuthNote(RESULT_NOTE, JsonSerialization.writeValueAsString(presentation));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to keep the OID4VP presentation", e);
        }
        return returnToExecution(authSession);
    }

    static Response fail(AuthenticationSessionModel authSession, String messageKey) {
        authSession.setAuthNote(FAILURE_NOTE, messageKey);
        return returnToExecution(authSession);
    }

    private static Response returnToExecution(AuthenticationSessionModel authSession) {
        String returnUrl = authSession.getAuthNote(RETURN_URL_NOTE);
        authSession.removeAuthNote(ALIAS_NOTE);
        authSession.removeAuthNote(RETURN_URL_NOTE);
        return Response.status(Response.Status.FOUND)
                .location(URI.create(returnUrl))
                .build();
    }
}
