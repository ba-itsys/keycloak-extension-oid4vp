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
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Binds an OID4VP login that carried no subject credential to the user who signed in.
 *
 * <p>A presentation without the subject credential identifies nobody, so the verifier continues the
 * login with a generated subject and the user signs in another way. This authenticator then derives a
 * subject for that user and sets the brokered identity to its identity key. The first broker login flow
 * stores that key as the link, and the credential the user receives afterwards carries the same
 * subject, so the next presentation reaches the same account. Deriving the subject keeps the user id
 * hidden from every verifier the credential is shown to.
 *
 * <p>Place it in the first broker login flow after the step that authenticates the user. Logins that
 * carry a subject credential pass through untouched, and so do logins of other identity providers.
 */
public class Oid4vpSubjectBindingAuthenticator implements Authenticator, AuthenticatorFactory {

    public static final String PROVIDER_ID = "oid4vp-subject-binding";

    private static final Logger LOG = Logger.getLogger(Oid4vpSubjectBindingAuthenticator.class);

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        SerializedBrokeredIdentityContext brokeredContext =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        UserModel user = context.getUser();

        if (brokeredContext == null || user == null || !bindsSubjectOf(brokeredContext)) {
            context.success();
            return;
        }

        ReferenceCredentialBinding binding = ReferenceCredentialBinding.of(context.getSession(), context.getRealm());
        String subject = binding.subjectOf(user.getId());
        bind(brokeredContext, subject, user.getUsername());
        brokeredContext.saveToAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        clearExistingLink(context, user, brokeredContext.getIdentityProviderId());
        LOG.debugf(
                "Bound the OID4VP login of identity provider '%s' to user '%s'",
                brokeredContext.getIdentityProviderId(), user.getId());
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Oid4vpSubjectCredentialOffer.offer(
                context.getSession(),
                context.getRealm(),
                authSession,
                user,
                Oid4vpMapperUtils.presentedCredentials(brokeredContext.deserialize(context.getSession(), authSession)),
                subject,
                config == null ? Map.of() : config.getConfig());
        context.success();
    }

    /**
     * Removes the link this identity provider already has to the user, so that the first broker login
     * flow can store the new one. A user who lost the issued credential arrives here a second time, and
     * Keycloak fails that flow with "already linked" for a user it has linked. Removing the link loses
     * nothing, because the subject is derived from the user and the new link holds the same identity.
     */
    private static void clearExistingLink(AuthenticationFlowContext context, UserModel user, String identityProvider) {
        if (StringUtil.isBlank(identityProvider)) {
            return;
        }
        if (context.getSession().users().removeFederatedIdentity(context.getRealm(), user, identityProvider)) {
            LOG.debugf(
                    "OID4VP subject binding: replacing the existing link of user '%s' to identity provider '%s'",
                    user.getId(), identityProvider);
        }
    }

    static boolean bindsSubjectOf(SerializedBrokeredIdentityContext brokeredContext) {
        return brokeredContext.getContextData().containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
    }

    // Derives the key as for a credential claim, so the credential issued afterwards reaches this identity.
    static void bind(SerializedBrokeredIdentityContext brokeredContext, String subject, String username) {
        brokeredContext.setId(Oid4vpIdentityKey.caseInsensitive(subject));
        brokeredContext.setBrokerUsername(username);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Subject Binding";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Binds an OID4VP login that carried no subject credential to the user who signed in, so the credential "
                + "issued afterwards identifies them on the next login.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Oid4vpSubjectCredentialOffer.CONFIG_PROPERTIES;
    }
}
