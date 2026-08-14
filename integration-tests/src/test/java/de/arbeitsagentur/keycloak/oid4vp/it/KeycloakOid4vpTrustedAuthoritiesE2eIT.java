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
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestTrustListServer;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * End to end coverage of the DCQL {@code trusted_authorities} constraint (OID4VP 1.0 §6.1.1).
 *
 * <p>The entries are inherited from the trust material identity providers serving a credential, so
 * every test drives the trust provider rather than the verifier: a provider backed by a trust list
 * advertises its URL as {@code etsi_tl} and the key identifiers of its issuance certificates as
 * {@code aki}, both as alternatives the wallet may match. Coverage is the advertised values, a
 * login where the wallet's credential issuer is covered by them, a login where it is not (the
 * provider then serves a trust list of a foreign authority, leaving the wallet without a credential
 * it may present), and a provider that advertises nothing.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpTrustedAuthoritiesE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    // A certificate authority the wallet has never issued a credential under
    private final X509Certificate foreignAuthority = generateForeignAuthority();

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void advertisesTheTrustListUrlAndItsAuthorityKeyIdentifiers() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        advertiseTrustedAuthorities();

        assertThat(trustedAuthoritiesOf(fetchCurrentRequestObject()))
                .containsExactly(
                        trustedAuthority("etsi_tl", wallet().pidTrustListUrl()),
                        trustedAuthority("aki", walletAuthorityKeyIdentifier()));
    }

    @Test
    void advertisesNothingWhileTheTrustProviderKeepsItsDomainPrivate() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        assertThat(trustedAuthoritiesOf(fetchCurrentRequestObject()))
                .as("the trust provider of the test realm does not advertise its trust domain")
                .isNull();
    }

    @Test
    void acceptsTheCredentialOfTheAdvertisedAuthority() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        advertiseTrustedAuthorities();

        performSameDeviceLogin("trusted-authority-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void rejectsTheCredentialOfAnUnlistedAuthority() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        try (TestTrustListServer foreignTrustList = TestTrustListServer.serving(foreignAuthority)) {
            useTrustList(foreignTrustList.url());

            assertPresentationIsRefused(
                    trustedAuthority("etsi_tl", foreignTrustList.url()),
                    trustedAuthority("aki", TestCertificates.subjectKeyIdentifierBase64Url(foreignAuthority)));
        }
    }

    /** Lets the trust material identity provider advertise the trust domain it is backed by. */
    private void advertiseTrustedAuthorities() {
        setTrustIdpConfig(Map.of(EtsiTrustListIdentityProviderConfig.ADVERTISE_TRUSTED_AUTHORITIES, "true"));
    }

    // Points the trust material identity provider at the given trust list and lets it advertise it
    private void useTrustList(String trustListUrl) {
        setTrustIdpConfig(Map.of(
                EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                trustListUrl,
                EtsiTrustListIdentityProviderConfig.ADVERTISE_TRUSTED_AUTHORITIES,
                "true"));
    }

    /**
     * Runs a login and asserts that the wallet refused to present because none of its credentials
     * satisfies the query. The advertised entry is checked before the wallet is driven, so a login
     * that never carried the constraint under test fails here instead of passing as a refusal.
     */
    @SafeVarargs
    private void assertPresentationIsRefused(Map<String, Object>... expectedTrustedAuthorities) throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();

        assertThat(trustedAuthoritiesOf(fetchRequestObject(walletUrl))).containsExactly(expectedTrustedAuthorities);

        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(walletUrl);
        assertLoginFailed(walletResponse, "no matching credentials");
    }

    private static Map<String, Object> trustedAuthority(String type, String value) {
        return Map.of("type", type, "values", List.of(value));
    }

    /** The {@code trusted_authorities} entries of the first credential of the DCQL query. */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> trustedAuthoritiesOf(SignedJWT requestJwt) throws Exception {
        Map<String, Object> dcqlQuery = requestJwt.getJWTClaimsSet().getJSONObjectClaim("dcql_query");
        Map<String, Object> credential = ((List<Map<String, Object>>) dcqlQuery.get("credentials")).get(0);
        return (List<Map<String, Object>>) credential.get("trusted_authorities");
    }

    // The identifier the wallet's credentials carry as their authority key identifier
    private String walletAuthorityKeyIdentifier() {
        return TestCertificates.subjectKeyIdentifierBase64Url(
                TestCertificates.parseCertificate(wallet().client().getCaCertificatePem()));
    }

    private static X509Certificate generateForeignAuthority() {
        try {
            return TestCertificates.generateCaCert(TestCertificates.generateEcKeyPair());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate the foreign certificate authority", e);
        }
    }
}
