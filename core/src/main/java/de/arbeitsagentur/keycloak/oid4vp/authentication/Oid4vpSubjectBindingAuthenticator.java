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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpIdentityKey;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.io.IOException;
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
 * login with a generated subject and the user signs in another way. This authenticator then sets the
 * brokered identity to the identity key of that user, before Keycloak stores the link at the end of
 * the first broker login flow. The credential the user receives afterwards carries their user id as
 * its subject, so the next presentation derives the same identity key and reaches the same account.
 *
 * <p>It then ends the login in Keycloak's credential offer, so the user leaves with the credential
 * they were missing. The user is entitled to that credential here as well, because the entitlement
 * follows from the login rather than from an administrator granting it beforehand.
 *
 * <p>Place it in the first broker login flow after the step that authenticates the user. Logins that
 * carry a subject credential, and logins of other identity providers, pass through untouched.
 */
public class Oid4vpSubjectBindingAuthenticator implements Authenticator, AuthenticatorFactory {

    public static final String PROVIDER_ID = "oid4vp-subject-binding";

    /** Credential configuration of the issuer, which is what the credential offer offers. */
    public static final String CREDENTIAL_CONFIGURATION_ID = "credentialConfigurationId";

    /** Client the credential offer is addressed to, which the wallet asks for the credential as. */
    public static final String OFFER_CLIENT_ID = "offerClientId";

    /** Whether the user is entitled to the credential when the offer is made. */
    public static final String GRANT_ENTITLEMENT = "grantEntitlement";

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

        if (brokeredContext == null || user == null || !bind(brokeredContext, user.getId(), user.getUsername())) {
            context.success();
            return;
        }

        brokeredContext.saveToAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        LOG.debugf(
                "Bound the OID4VP login of identity provider '%s' to user '%s'",
                brokeredContext.getIdentityProviderId(), user.getId());
        offerSubjectCredential(context, user);
        context.success();
    }

    /**
     * Ends the login in Keycloak's credential offer required action, so the user receives the
     * credential that identifies them next time. The action reads which credential to offer from the
     * client note it is triggered with, and skips the offer when the user already holds it.
     *
     * <p>Nothing has to travel from this login to the issuance, because the credential carries the id
     * of the user this login was just bound to.
     */
    private void offerSubjectCredential(AuthenticationFlowContext context, UserModel user) {
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
        if (grantsEntitlement(config)) {
            entitleUser(context.getSession(), user, credentialScope);
        }

        VerifiableCredentialOfferActionConfig offerConfig =
                offerFor(credentialConfigurationId, config.get(OFFER_CLIENT_ID));
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        try {
            authSession.setClientNote(Constants.KC_ACTION_PARAMETER, offerConfig.asEncodedParameter());
            authSession.setClientNote(Constants.KC_ACTION_PARAMETER_SKIP_IF_EXISTS, Boolean.TRUE.toString());
            authSession.addRequiredAction(OID4VCIConstants.VERIFIABLE_CREDENTIAL_OFFER_PROVIDER_ID);
        } catch (IOException e) {
            LOG.errorf(
                    e,
                    "OID4VP subject binding: failed to build the credential offer for configuration '%s'",
                    credentialConfigurationId);
        }
    }

    /**
     * The offer of the credential. It is pre-authorized, because the user is authenticated in this
     * login already and the wallet redeems it without authenticating again. Keycloak ties the
     * pre-authorized code to this login session.
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

    /** Whether this authenticator entitles the user, which it does unless it is configured not to. */
    static boolean grantsEntitlement(Map<String, String> config) {
        return Boolean.parseBoolean(config.getOrDefault(GRANT_ENTITLEMENT, Boolean.TRUE.toString()));
    }

    /**
     * Entitles the user to the credential, because Keycloak only offers a credential to a user who is
     * entitled to it. The entitlement follows from this login, so it is granted here instead of by an
     * administrator beforehand.
     */
    private static void entitleUser(KeycloakSession session, UserModel user, CredentialScopeModel credentialScope) {
        if (OID4VCUtil.hasVerifiableCredential(session, user, credentialScope)) {
            return;
        }
        session.users()
                .addVerifiableCredential(
                        user.getId(), new UserVerifiableCredentialModel(null, credentialScope.getId()));
        LOG.debugf(
                "OID4VP subject binding: entitled user '%s' to the credential of scope '%s'",
                user.getId(), credentialScope.getName());
    }

    /**
     * Sets the brokered identity to the identity key of the given user, when the verifier generated
     * the subject of this login because no credential carried one. The identity key is derived the
     * way it is derived from a credential claim, so the credential the user receives afterwards
     * reaches this identity.
     *
     * @return whether the brokered identity was changed
     */
    static boolean bind(SerializedBrokeredIdentityContext brokeredContext, String userId, String username) {
        if (!brokeredContext.getContextData().containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY)) {
            return false;
        }
        brokeredContext.setId(Oid4vpIdentityKey.caseInsensitive(userId));
        brokeredContext.setBrokerUsername(username);
        return true;
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
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing to require of the user.
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // No configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No configuration.
    }

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

        ProviderConfigProperty grantEntitlement = new ProviderConfigProperty();
        grantEntitlement.setName(GRANT_ENTITLEMENT);
        grantEntitlement.setLabel("Grant Entitlement");
        grantEntitlement.setHelpText("Entitles the user to the offered credential. Keycloak only offers a credential "
                + "to a user who is entitled to it. Turn this off when an administrator grants the entitlement.");
        grantEntitlement.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        grantEntitlement.setDefaultValue(Boolean.TRUE.toString());

        return List.of(credentialConfigurationId, offerClientId, grantEntitlement);
    }
}
