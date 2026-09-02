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
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils;
import org.keycloak.protocol.oid4vc.utils.OID4VCUtil;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Binds an OID4VP login that carried no subject credential to the user who signed in.
 *
 * <p>A presentation without the subject credential identifies nobody, so the verifier continues the
 * login with a generated subject and the user signs in another way. This authenticator then derives a
 * subject for that user and sets the brokered identity to its identity key, so that the first broker
 * login flow stores that key as the link and the credential the user receives afterwards carries the
 * same subject, which makes the next presentation reach the same account. The subject is derived rather
 * than the user id, so every verifier the credential is shown to reads an opaque value.
 *
 * <p>Place it in the first broker login flow after the step that authenticates the user. Logins that
 * carry a subject credential pass through untouched, and so do logins of other identity providers.
 */
public class Oid4vpSubjectBindingAuthenticator implements Authenticator, AuthenticatorFactory {

    public static final String PROVIDER_ID = "oid4vp-subject-binding";

    public static final String CREDENTIAL_CONFIGURATION_ID = "credentialConfigurationId";

    public static final String OFFER_CLIENT_ID = "offerClientId";

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
        offerSubjectCredential(context, binding, brokeredContext, user, subject);
        context.success();
    }

    /**
     * Removes the link this identity provider already has to the user, so that the first broker login
     * flow can store the one this login establishes. A user who lost the issued credential arrives here
     * a second time, and Keycloak fails the first broker login flow with "already linked" for a user it
     * has linked. Removing the link loses nothing, because the subject is derived from the user and the
     * link stored a moment later holds the same identity.
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

    /**
     * Ends the login in Keycloak's credential offer required action, so that the user receives the
     * credential that identifies them next time. The action reads which credential to offer from the
     * client note it is triggered with.
     */
    private void offerSubjectCredential(
            AuthenticationFlowContext context,
            ReferenceCredentialBinding binding,
            SerializedBrokeredIdentityContext brokeredContext,
            UserModel user,
            String subject) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel == null ? Map.of() : configModel.getConfig();
        String credentialConfigurationId = config.get(CREDENTIAL_CONFIGURATION_ID);
        if (StringUtil.isBlank(credentialConfigurationId)) {
            LOG.debug("OID4VP subject binding: no credential configuration id is set, so no credential is offered");
            return;
        }
        RealmModel realm = context.getRealm();
        CredentialScopeModel credentialScope = CredentialScopeUtils.findCredentialScopeModelByConfigurationId(
                realm, realm::getClientScopesStream, credentialConfigurationId);
        if (credentialScope == null) {
            LOG.warnf(
                    "OID4VP subject binding: realm '%s' has no credential scope for configuration '%s', "
                            + "so no credential is offered",
                    realm.getName(), credentialConfigurationId);
            return;
        }
        entitleUser(context, binding, brokeredContext, user, credentialScope, subject);

        VerifiableCredentialOfferActionConfig offerConfig =
                offerFor(credentialConfigurationId, config.get(OFFER_CLIENT_ID));
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        try {
            authSession.setClientNote(Constants.KC_ACTION_PARAMETER, offerConfig.asEncodedParameter());
            // The offer is made even when the user is entitled already, because arriving here means the
            // presentation carried no subject credential and what the user holds does not identify them.
            authSession.addRequiredAction(OID4VCIConstants.VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID);
        } catch (IOException e) {
            LOG.errorf(
                    e,
                    "OID4VP subject binding: failed to build the credential offer for configuration '%s'",
                    credentialConfigurationId);
        }
    }

    /**
     * Builds a pre-authorized credential offer. The user is authenticated in this login already, so the
     * wallet redeems the offer without authenticating again and Keycloak ties the pre-authorized code to
     * this login session.
     */
    static VerifiableCredentialOfferActionConfig offerFor(String credentialConfigurationId, String offerClientId) {
        VerifiableCredentialOfferActionConfig offerConfig = new VerifiableCredentialOfferActionConfig();
        offerConfig.setCredentialConfigurationId(credentialConfigurationId);
        offerConfig.setPreAuthorized(true);
        if (StringUtil.isNotBlank(offerClientId)) {
            offerConfig.setClientId(offerClientId);
        }
        return offerConfig;
    }

    /**
     * Entitles the user to the credential, because Keycloak only offers a credential to a user who is
     * entitled to it. The entitlement records the subject of this account and the reference credential
     * binding of this presentation, and since the pre-authorized code is redeemed in a session of its
     * own, the entitlement is the only thing of this login the issuance sees. An entitlement that exists
     * already is replaced, so a login after a change of the bound claims issues a credential that
     * matches the presentation of today.
     */
    private static void entitleUser(
            AuthenticationFlowContext context,
            ReferenceCredentialBinding binding,
            SerializedBrokeredIdentityContext brokeredContext,
            UserModel user,
            CredentialScopeModel credentialScope,
            String subject) {
        KeycloakSession session = context.getSession();
        Map<String, List<String>> credentialAttributes = new LinkedHashMap<>();
        credentialAttributes.put(ReferenceCredentialBinding.SUBJECT_ATTRIBUTE, List.of(subject));
        String referenceBinding = binding.referenceBindingOf(
                presentedCredentials(context, brokeredContext),
                // The subject credential is the one being issued, so the presentation cannot carry it.
                null);
        if (referenceBinding != null) {
            credentialAttributes.put(ReferenceCredentialBinding.REFERENCE_BINDING_ATTRIBUTE, List.of(referenceBinding));
        }

        if (OID4VCUtil.hasVerifiableCredential(session, user, credentialScope)) {
            session.users().removeVerifiableCredential(user.getId(), credentialScope.getId());
        }
        UserVerifiableCredentialModel entitlement = new UserVerifiableCredentialModel(null, credentialScope.getId());
        entitlement.setUserAttributes(credentialAttributes);
        session.users().addVerifiableCredential(user.getId(), entitlement);
        LOG.debugf(
                "OID4VP subject binding: entitled user '%s' to the credential of scope '%s'",
                user.getId(), credentialScope.getName());
    }

    private static PresentedCredentials presentedCredentials(
            AuthenticationFlowContext context, SerializedBrokeredIdentityContext brokeredContext) {
        return Oid4vpMapperUtils.presentedCredentials(
                brokeredContext.deserialize(context.getSession(), context.getAuthenticationSession()));
    }

    /**
     * Reports whether this login needs a subject at all. A login that carried its own subject identifies
     * the user already, and a login of another identity provider is none of this authenticator's
     * business.
     */
    static boolean bindsSubjectOf(SerializedBrokeredIdentityContext brokeredContext) {
        return brokeredContext.getContextData().containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
    }

    /**
     * Sets the brokered identity to the identity key of the given subject, derived the same way it is
     * derived from a credential claim, so that the credential the user receives afterwards reaches this
     * identity.
     */
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
        ProviderConfigProperty credentialConfigurationId = new ProviderConfigProperty();
        credentialConfigurationId.setName(CREDENTIAL_CONFIGURATION_ID);
        credentialConfigurationId.setLabel("Credential Configuration ID");
        credentialConfigurationId.setHelpText("Credential configuration of this Keycloak that the credential offer "
                + "offers. Empty means no offer, and the user signs in with a password on every login.");
        credentialConfigurationId.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty offerClientId = new ProviderConfigProperty();
        offerClientId.setName(OFFER_CLIENT_ID);
        offerClientId.setLabel("Offer Client ID");
        offerClientId.setHelpText("Client the credential offer is addressed to. The wallet asks for the credential as "
                + "this client, so it needs OID4VCI enabled.");
        offerClientId.setType(ProviderConfigProperty.STRING_TYPE);

        return List.of(credentialConfigurationId, offerClientId);
    }
}
