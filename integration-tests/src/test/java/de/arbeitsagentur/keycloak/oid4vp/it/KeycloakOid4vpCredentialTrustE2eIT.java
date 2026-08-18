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

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * End to end coverage of trust material identity providers that declare the credential types they
 * serve.
 *
 * <p>A response can carry credentials of several trust domains, so trust is resolved per credential:
 * a provider scoped to one credential type verifies presentations of that type and advertises its
 * trusted authorities on that credential's DCQL entry, while a credential type no provider serves
 * has no trust material and cannot be verified at all.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpCredentialTrustE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void credentialOfTheServedTypeIsVerifiedAgainstThatTrustDomain() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        serveOnly(Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT);
        replaceDcqlMappers(Oid4vpTestKeycloakSetup.sdJwtPidMappers());

        performSameDeviceLogin("served-credential-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void credentialTypeNoProviderServesCannotBeVerified() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        // The trust domain of the realm is responsible for the SD-JWT PID only, so the mDoc PID has
        // no trust anchors even though the same authority issued it.
        serveOnly(Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT);
        replaceDcqlMappers(Oid4vpTestKeycloakSetup.mdocPidMappers());

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(flow.getSameDeviceWalletUrl());

        // A credential type no provider serves resolves to empty trust material: verification
        // fails with "No trusted keys available for mDoc signature verification" (or "no trusted
        // key matched"), which the endpoint returns as the error_description.
        assertLoginFailed(walletResponse, "no trusted key");
    }

    @Test
    void everyCredentialAdvertisesTheAuthoritiesOfItsOwnTrustDomain() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        setTrustIdpConfig(Map.of(
                EtsiTrustListIdentityProviderConfig.SERVED_CREDENTIAL_TYPES,
                Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT,
                EtsiTrustListIdentityProviderConfig.ADVERTISE_TRUSTED_AUTHORITIES,
                "etsi_tl"));

        SignedJWT requestObject = fetchCurrentRequestObject();

        assertThat(trustedAuthorityTypesOf(requestObject, Oid4vpTestKeycloakSetup.SD_JWT_PID_CREDENTIAL_ID))
                .containsExactly("etsi_tl");
        assertThat(trustedAuthorityTypesOf(requestObject, Oid4vpTestKeycloakSetup.MDOC_PID_CREDENTIAL_ID))
                .as("a credential no provider serves carries no trusted_authorities")
                .isEmpty();
    }

    /** Restricts the trust material identity provider of the realm to the given credential type. */
    private void serveOnly(String credentialType) {
        setTrustIdpConfig(Map.of(EtsiTrustListIdentityProviderConfig.SERVED_CREDENTIAL_TYPES, credentialType));
    }

    /** The {@code trusted_authorities} types of one credential of the DCQL query. */
    @SuppressWarnings("unchecked")
    private List<String> trustedAuthorityTypesOf(SignedJWT requestJwt, String credentialId) throws Exception {
        Map<String, Object> dcqlQuery = requestJwt.getJWTClaimsSet().getJSONObjectClaim("dcql_query");
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) dcqlQuery.get("credentials");
        Map<String, Object> credential = credentials.stream()
                .filter(entry -> credentialId.equals(entry.get("id")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("The query has no credential '" + credentialId + "'"));
        List<Map<String, Object>> trustedAuthorities =
                (List<Map<String, Object>>) credential.get("trusted_authorities");
        return trustedAuthorities == null
                ? List.of()
                : trustedAuthorities.stream()
                        .map(entry -> (String) entry.get("type"))
                        .toList();
    }
}
