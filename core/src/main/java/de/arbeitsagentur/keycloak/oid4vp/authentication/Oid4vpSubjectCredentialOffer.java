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
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils;
import org.keycloak.protocol.oid4vc.utils.OID4VCUtil;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Offers a user the subject credential of this Keycloak, so that the next presentation identifies
 * them. A presentation that lacks the subject credential is bound to a user through a subject derived
 * from the user, and the offered credential carries that subject.
 */
public final class Oid4vpSubjectCredentialOffer {

    public static final String CREDENTIAL_CONFIGURATION_ID = "credentialConfigurationId";

    public static final String OFFER_CLIENT_ID = "offerClientId";

    static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(CREDENTIAL_CONFIGURATION_ID)
            .label("Credential Configuration ID")
            .helpText("Credential configuration of this Keycloak that is offered to the user. When empty, nothing is "
                    + "offered and the user has to sign in another way on every login.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(OFFER_CLIENT_ID)
            .label("Offer Client ID")
            .helpText("Client the credential offer is addressed to. The wallet asks for the credential as this "
                    + "client, so it needs OID4VCI enabled.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .build();

    private static final Logger LOG = Logger.getLogger(Oid4vpSubjectCredentialOffer.class);

    private Oid4vpSubjectCredentialOffer() {}

    /**
     * Entitles the user to the configured credential and ends the authentication in Keycloak's
     * credential offer required action. Does nothing without a configured credential configuration.
     */
    public static void offer(
            KeycloakSession session,
            RealmModel realm,
            AuthenticationSessionModel authSession,
            UserModel user,
            PresentedCredentials presented,
            String subject,
            Map<String, String> config) {
        String credentialConfigurationId = config.get(CREDENTIAL_CONFIGURATION_ID);
        if (StringUtil.isBlank(credentialConfigurationId)) {
            LOG.debug("OID4VP subject binding: no credential configuration id is set, so no credential is offered");
            return;
        }
        CredentialScopeModel credentialScope = CredentialScopeUtils.findCredentialScopeModelByConfigurationId(
                realm, realm::getClientScopesStream, credentialConfigurationId);
        if (credentialScope == null) {
            LOG.warnf(
                    "OID4VP subject binding: realm '%s' has no credential scope for configuration '%s', "
                            + "so no credential is offered",
                    realm.getName(), credentialConfigurationId);
            return;
        }
        entitle(session, realm, user, presented, credentialScope, subject);

        VerifiableCredentialOfferActionConfig offerConfig =
                offerFor(credentialConfigurationId, config.get(OFFER_CLIENT_ID));
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
     * matches the current presentation.
     */
    private static void entitle(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            PresentedCredentials presented,
            CredentialScopeModel credentialScope,
            String subject) {
        Map<String, List<String>> credentialAttributes = new LinkedHashMap<>();
        credentialAttributes.put(ReferenceCredentialBinding.SUBJECT_ATTRIBUTE, List.of(subject));
        String referenceBinding = ReferenceCredentialBinding.of(session, realm)
                .referenceBindingOf(
                        presented,
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
}
