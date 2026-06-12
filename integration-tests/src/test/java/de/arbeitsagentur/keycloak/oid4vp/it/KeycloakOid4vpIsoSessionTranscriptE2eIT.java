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
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWalletConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWalletConfigBuilder;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

// End-to-end test against a wallet using the ISO 18013-7 mDoc session transcript
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpIsoSessionTranscriptE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet(config = IsoSessionTranscriptWalletConfig.class)
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    public static class IsoSessionTranscriptWalletConfig implements TestWalletConfig {
        @Override
        public TestWalletConfigBuilder configure(TestWalletConfigBuilder wallet) {
            return wallet.sessionTranscript("iso");
        }
    }

    @Test
    void mdocWithIsoSessionTranscript() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """;
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.DCQL_QUERY, mdocDcqlQuery));

        performSameDeviceLogin("iso-transcript-user");
        flow.assertLoginSucceeded();
    }
}
