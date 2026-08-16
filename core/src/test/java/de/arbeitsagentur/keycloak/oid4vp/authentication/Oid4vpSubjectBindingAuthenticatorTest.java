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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpIdentityKey;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext.ContextDataEntry;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;

class Oid4vpSubjectBindingAuthenticatorTest {

    /** What the authenticator derives from the user id and the credential carries afterwards. */
    private static final String SUBJECT = "Zm9vYmFyLXN1YmplY3Qtb2YtdGhlLXVzZXI";

    @Test
    void bindsAGeneratedSubjectLoginToTheUserWhoSignedIn() {
        SerializedBrokeredIdentityContext brokeredContext = generatedSubjectContext("oid4vp-3f2c");

        assertThat(Oid4vpSubjectBindingAuthenticator.bindsSubjectOf(brokeredContext))
                .isTrue();
        Oid4vpSubjectBindingAuthenticator.bind(brokeredContext, SUBJECT, "alice");

        assertThat(brokeredContext.getId()).isEqualTo(Oid4vpIdentityKey.caseInsensitive(SUBJECT));
        assertThat(brokeredContext.getBrokerUsername()).isEqualTo("alice");
    }

    @Test
    void leavesALoginThatCarriedItsSubjectUntouched() {
        SerializedBrokeredIdentityContext brokeredContext = new SerializedBrokeredIdentityContext();
        brokeredContext.setId("identity-of-the-presented-subject");
        brokeredContext.setBrokerUsername("subject-from-the-credential");

        assertThat(Oid4vpSubjectBindingAuthenticator.bindsSubjectOf(brokeredContext))
                .as("a login that identifies its user needs no binding")
                .isFalse();
    }

    @Test
    void theBoundIdentityIsTheOneTheIssuedCredentialWillReach() {
        SerializedBrokeredIdentityContext brokeredContext = generatedSubjectContext("oid4vp-3f2c");
        Oid4vpSubjectBindingAuthenticator.bind(brokeredContext, SUBJECT, "alice");

        // The credential the user receives carries that subject, so the next presentation has to
        // derive exactly the identity this login stored.
        VerifiedCredential issuedCredential = new VerifiedCredential(
                "employee",
                "https://kc.example/realms/company",
                "https://kc.example/badge",
                Map.of("sub", SUBJECT),
                PresentationType.SD_JWT);

        assertThat(issuedCredential.generateCaseInsensitiveIdentityKey(SUBJECT)).isEqualTo(brokeredContext.getId());
    }

    @Test
    void offersTheConfiguredCredentialAsTheConfiguredClient() {
        VerifiableCredentialOfferActionConfig offer =
                Oid4vpSubjectBindingAuthenticator.offerFor("employee-credential", "wallet-vci");

        assertThat(offer.getCredentialConfigurationId()).isEqualTo("employee-credential");
        assertThat(offer.getClientId()).isEqualTo("wallet-vci");
        assertThat(offer.getPreAuthorized())
                .as("the user is authenticated in this login, so the wallet redeems the offer without signing in")
                .isTrue();
    }

    @Test
    void leavesTheOfferClientUnsetWhenNoneIsConfigured() {
        VerifiableCredentialOfferActionConfig offer =
                Oid4vpSubjectBindingAuthenticator.offerFor("employee-credential", "  ");

        assertThat(offer.getClientId()).isNull();
    }

    @Test
    void isRegisteredUnderTheIdThatFlowsReferenceAndRunsOnlyAfterAuthentication() {
        Oid4vpSubjectBindingAuthenticator authenticator = new Oid4vpSubjectBindingAuthenticator();

        assertThat(authenticator.getId()).isEqualTo("oid4vp-subject-binding");
        assertThat(authenticator.requiresUser())
                .as("it binds the login to the user who signed in, so it needs that user")
                .isTrue();
        assertThat(authenticator.isConfigurable()).isTrue();
        assertThat(authenticator.getRequirementChoices())
                .containsExactly(
                        AuthenticationExecutionModel.Requirement.REQUIRED,
                        AuthenticationExecutionModel.Requirement.DISABLED);
    }

    @Test
    void declaresTheOfferSettings() {
        List<ProviderConfigProperty> properties = new Oid4vpSubjectBindingAuthenticator().getConfigProperties();

        assertThat(properties)
                .as("the entitlement is not configurable, it is what carries the subject to the issuance")
                .extracting(ProviderConfigProperty::getName)
                .containsExactly(
                        Oid4vpSubjectBindingAuthenticator.CREDENTIAL_CONFIGURATION_ID,
                        Oid4vpSubjectBindingAuthenticator.OFFER_CLIENT_ID);
    }

    private static SerializedBrokeredIdentityContext generatedSubjectContext(String generatedSubject) {
        SerializedBrokeredIdentityContext brokeredContext = new SerializedBrokeredIdentityContext();
        brokeredContext.setId(Oid4vpIdentityKey.caseInsensitive(generatedSubject));
        brokeredContext.setBrokerUsername(generatedSubject);
        brokeredContext
                .getContextData()
                .put(
                        Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY,
                        ContextDataEntry.create(String.class.getName(), generatedSubject));
        return brokeredContext;
    }
}
