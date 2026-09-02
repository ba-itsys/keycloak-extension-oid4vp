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
package de.arbeitsagentur.keycloak.oid4vp.it;

import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT;
import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.sdJwtAttributeMapper;
import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.sdJwtSessionMapper;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * End to end tests for DCQL claim_sets generated from mapper claim set ids. The wallet discloses the
 * most preferred claim set it can satisfy, and the verifier accepts only presentations that satisfy
 * one of the requested sets.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpClaimSetsE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void walletDisclosesPreferredClaimSet() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // Option 1-full asks for family_name, given_name and birthdate, option 2-min only for
        // family_name and birthdate. The wallet's PID carries all of them, so it has to disclose the
        // preferred option.
        replaceDcqlMappers(List.of(
                sdJwtAttributeMapper("cs-family-name", SD_JWT_PID_VCT, "family_name", "lastName", null),
                sdJwtAttributeMapper("cs-given-name", SD_JWT_PID_VCT, "given_name", "firstName", "1-full"),
                sdJwtSessionMapper(
                        "cs-birthdate", SD_JWT_PID_VCT, "birthdate", "credentialBirthdate", "1-full,2-min")));

        performSameDeviceLogin("claimset-full-user");
        flow.assertLoginSucceeded();

        UserRepresentation user = singleOid4vpUser();
        assertThat(user.getFirstName())
                .as("given_name from the preferred claim set must be disclosed and mapped")
                .isEqualTo(walletPidClaim("given_name"));
        assertThat(user.getLastName()).isEqualTo(walletPidClaim("family_name"));
    }

    @Test
    void walletFallsBackToSatisfiableClaimSet() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // Option 1-full asks for family_name, email and given_name, option 2-min only for
        // family_name and given_name. The wallet's PID has no email claim, so only the fallback
        // option can be satisfied.
        replaceDcqlMappers(List.of(
                sdJwtAttributeMapper("cs-family-name", SD_JWT_PID_VCT, "family_name", "lastName", null),
                sdJwtAttributeMapper("cs-email", SD_JWT_PID_VCT, "email", "email", "1-full"),
                sdJwtAttributeMapper("cs-given-name", SD_JWT_PID_VCT, "given_name", "firstName", "1-full,2-min")));

        performSameDeviceLogin("claimset-fallback-user");
        flow.assertLoginSucceeded();

        UserRepresentation user = singleOid4vpUser();
        assertThat(user.getFirstName())
                .as("given_name from the fallback claim set must be disclosed and mapped")
                .isEqualTo(walletPidClaim("given_name"));
        assertThat(user.getLastName()).isEqualTo(walletPidClaim("family_name"));
        // The first-broker-login form fills the email field only when the mappers left it empty, so a
        // form-generated address proves the wallet disclosed no email claim.
        assertThat(user.getEmail())
                .as("email is not part of the satisfied claim set and must not come from the credential")
                .startsWith("claimset-fallback-user");
    }

    @Test
    void walletDisclosesAlternativeClaimWhenTheClaimIsAbsent() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // The German PID rulebook calls the birth name birth_name while the EUDI rulebook, which the
        // wallet's PID follows, calls it birth_family_name. The mapper reads birth_name with
        // birth_family_name as its alternative, so only the alternative gets an answer. Together with
        // the claim set ids of the email mapper that makes four generated options, of which the
        // wallet can satisfy only the two that ask for the alternative without email.
        IdentityProviderMapperRepresentation birthName =
                sdJwtAttributeMapper("cs-birth-name", SD_JWT_PID_VCT, "birth_name", "lastName", null);
        birthName.getConfig().put("claim.alternatives", "birth_family_name");
        replaceDcqlMappers(List.of(
                sdJwtAttributeMapper("cs-given-name", SD_JWT_PID_VCT, "given_name", "firstName", "1-full,2-min"),
                sdJwtAttributeMapper("cs-email", SD_JWT_PID_VCT, "email", "email", "1-full"),
                birthName));

        performSameDeviceLogin("claimset-alternative-user");
        flow.assertLoginSucceeded();

        UserRepresentation user = singleOid4vpUser();
        assertThat(user.getLastName())
                .as("birth_family_name is disclosed as the alternative of birth_name and mapped by the same mapper")
                .isEqualTo(walletPidClaim("birth_family_name"));
        assertThat(user.getFirstName()).isEqualTo(walletPidClaim("given_name"));
        assertThat(user.getEmail())
                .as("the satisfied option is the one without email")
                .startsWith("claimset-alternative-user");
    }

    private UserRepresentation singleOid4vpUser() {
        assertThat(countOid4vpUsers()).isEqualTo(1);
        return realm.admin().users().list(0, 100).stream()
                .filter(user -> !"admin".equals(user.getUsername()) && !"test".equals(user.getUsername()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No brokered OID4VP user found"));
    }

    private String walletPidClaim(String claim) {
        return wallet().client().getCredentialsByType(SD_JWT_PID_VCT).stream()
                .map(credential -> credential.claims().get(claim))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Wallet PID has no claim " + claim));
    }
}
