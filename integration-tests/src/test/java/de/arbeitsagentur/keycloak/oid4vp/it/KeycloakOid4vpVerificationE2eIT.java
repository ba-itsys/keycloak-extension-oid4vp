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

import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import io.github.dominikschlosser.eudi.CredentialFormat;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpVerificationE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void revokedSdJwtCredentialIsRejected() throws Exception {
        assertRevokedCredentialIsRejected("SD-JWT");
    }

    @Test
    void revokedMdocCredentialIsRejected() throws Exception {
        replaceDcqlMappers(Oid4vpTestKeycloakSetup.mdocPidMappers());
        wallet().client().setPreferredFormat(CredentialFormat.MSO_MDOC);

        try {
            assertRevokedCredentialIsRejected("mDoc", "eu.europa.ec.eudi.pid.1");
        } finally {
            wallet().client().clearPreferredFormat();
        }
    }

    @Test
    void trustListCacheDoesNotBypassSigningCertChanges() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("trustlist-cache-user");
        flow.assertLoginSucceeded();

        KeyPair wrongKeyPair = TestCertificates.generateEcKeyPair();
        X509Certificate wrongCert = TestCertificates.generateCaCert(wrongKeyPair);
        String wrongCertPem = TestCertificates.toPem("CERTIFICATE", wrongCert.getEncoded());
        setTrustIdpConfig(Map.of(EtsiTrustListIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM, wrongCertPem));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        // With the trust list unverifiable, the credential has no trust anchors left: verification
        // fails with "No trusted keys available for ... signature verification" (or "no trusted
        // key matched"), which the endpoint returns as the error_description.
        assertLoginFailed(walletResponse, "no trusted key");
    }

    @Test
    void trustListLoTETypeMismatchIsRejected() throws Exception {
        setTrustIdpConfig(Map.of(
                EtsiTrustListIdentityProviderConfig.TRUST_LIST_LOTE_TYPE,
                "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        // The trust material provider rejects the list with "Trust list LoTE type mismatch:
        // expected ... but got ..." (EtsiTrustListIdentityProvider), which the endpoint returns
        // as the error_description.
        assertLoginFailed(walletResponse, "lote type mismatch");
    }

    @Test
    void activeCredentialPassesStatusListVerification() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        performSameDeviceLogin("statuslist-active-user");
        flow.assertLoginSucceeded();
    }
}
