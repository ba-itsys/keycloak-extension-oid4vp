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

import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.PRINCIPAL_CLAIM;
import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT;
import static de.arbeitsagentur.keycloak.oid4vp.it.Oid4vpTestKeycloakSetup.sdJwtAttributeMapper;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import io.github.dominikschlosser.eudi.CredentialFormat;
import io.github.dominikschlosser.eudi.IssueRequest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * End to end coverage of one credential entry accepting several VCTs: the mappers name the EUDI
 * PID and the German PID together, the DCQL entry lists both in {@code vct_values}, and a wallet
 * holding either PID signs in through the same mappers. The two rulebooks name the birth name
 * differently, which the alternative claim of the birth name mapper bridges.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpCredentialTypesE2eIT extends AbstractOid4vpE2eTest {

    private static final String GERMAN_PID_VCT = "urn:eudi:pid:de:1";
    private static final String BOTH_PID_VCTS = SD_JWT_PID_VCT + ", " + GERMAN_PID_VCT;
    private static final String GERMAN_PID_TEMPLATE = "german-pid-sdjwt";

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void entryAcceptingBothPidTypesListsThemAndSignsInWithTheEudiPid() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        replaceDcqlMappers(bothPidMappers());

        assertThat(vctValuesOfFirstCredential(fetchCurrentRequestObject()))
                .containsExactly(SD_JWT_PID_VCT, GERMAN_PID_VCT);

        performSameDeviceLogin("eudi-pid-user");
        flow.assertLoginSucceeded();

        UserRepresentation user = singleOid4vpUser();
        assertThat(user.getFirstName()).isEqualTo(walletPidClaim(SD_JWT_PID_VCT, "given_name"));
        assertThat(user.getLastName())
                .as("the EUDI PID carries the birth name under the mapper's own claim path")
                .isEqualTo(walletPidClaim(SD_JWT_PID_VCT, "birth_family_name"));
    }

    @Test
    void walletHoldingTheGermanPidSignsInThroughTheSameEntry() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        replaceDcqlMappers(bothPidMappers());

        // The German PID rulebook has no administrative number, so the test principal is added.
        wallet().client().deleteCredentialsByType(SD_JWT_PID_VCT);
        wallet().client()
                .issueCredential(IssueRequest.fromTemplate(GERMAN_PID_TEMPLATE).claim(PRINCIPAL_CLAIM, "DE-123456"));
        try {
            performSameDeviceLogin("german-pid-user");
            flow.assertLoginSucceeded();

            UserRepresentation user = singleOid4vpUser();
            assertThat(user.getFirstName()).isEqualTo(walletPidClaim(GERMAN_PID_VCT, "given_name"));
            assertThat(user.getLastName())
                    .as("the German PID carries the birth name under the alternative claim path")
                    .isEqualTo(walletPidClaim(GERMAN_PID_VCT, "birth_name"));
        } finally {
            wallet().client().deleteCredentialsByType(GERMAN_PID_VCT);
            wallet().client().issueCredential(IssueRequest.pid(CredentialFormat.SD_JWT));
        }
    }

    /** Mappers naming both PID types, reading the birth name under either rulebook's claim name. */
    private static List<IdentityProviderMapperRepresentation> bothPidMappers() {
        IdentityProviderMapperRepresentation birthName =
                sdJwtAttributeMapper("ct-birth-name", BOTH_PID_VCTS, "birth_family_name", "lastName", null);
        birthName.getConfig().put("claim.alternatives", "birth_name");
        return List.of(
                sdJwtAttributeMapper("ct-given-name", BOTH_PID_VCTS, "given_name", "firstName", null), birthName);
    }

    @SuppressWarnings("unchecked")
    private static List<String> vctValuesOfFirstCredential(SignedJWT requestJwt) throws Exception {
        Map<String, Object> dcqlQuery = requestJwt.getJWTClaimsSet().getJSONObjectClaim("dcql_query");
        Map<String, Object> credential = ((List<Map<String, Object>>) dcqlQuery.get("credentials")).get(0);
        return (List<String>) ((Map<String, Object>) credential.get("meta")).get("vct_values");
    }

    private UserRepresentation singleOid4vpUser() {
        assertThat(countOid4vpUsers()).isEqualTo(1);
        return realm.admin().users().list(0, 100).stream()
                .filter(user -> !"admin".equals(user.getUsername()) && !"test".equals(user.getUsername()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No brokered OID4VP user found"));
    }

    private String walletPidClaim(String vct, String claim) {
        return wallet().client().getCredentialsByType(vct).stream()
                .map(credential -> credential.claims().get(claim))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Wallet PID " + vct + " has no claim " + claim));
    }
}
