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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import io.github.dominikschlosser.oid4vc.CredentialFormat;
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
        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.DCQL_QUERY, mdocDcqlQuery));
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
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM, wrongCertPem));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        assertLoginFailed(walletResponse, "trust list", "signature", "failed", "authentication");
    }

    @Test
    void trustListLoTETypeMismatchIsRejected() throws Exception {
        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.TRUST_LIST_LOTE_TYPE,
                "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"));

        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        var walletResponse = flow.submitToWallet(walletUrl);

        assertLoginFailed(walletResponse, "trust list", "lote", "mismatch", "authentication");
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
