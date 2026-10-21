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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWalletConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWalletConfigBuilder;
import io.github.dominikschlosser.eudi.ActivityLogEntry;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpEncryptedRequestE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet(config = EncryptedRequestWalletConfig.class)
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    public static class EncryptedRequestWalletConfig implements TestWalletConfig {
        @Override
        public TestWalletConfigBuilder configure(TestWalletConfigBuilder wallet) {
            return wallet.requireEncryptedRequest();
        }
    }

    @Test
    void requestObjectFetchedWithPostIsEncryptedForTheWallet() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        wallet.client().clearActivityLog();
        // The wallet sends its encryption key in wallet_metadata, which only a POST to the
        // request_uri carries (OID4VP 1.0 section 5.10).
        setIdpConfig(Map.of(Oid4vpIdentityProviderConfig.REQUEST_URI_METHOD_POST, "true"));

        performSameDeviceLogin("enc-request-user");
        flow.assertLoginSucceeded();

        ActivityLogEntry fetch = requestObjectFetch();
        assertThat(fetch.details()).containsEntry("method", "POST");
    }

    @Test
    void requestObjectFetchedWithGetStaysSigned() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        wallet.client().clearActivityLog();
        // A GET carries no wallet_metadata, so the verifier has no key to encrypt to. A wallet that
        // does not require encryption accepts the signed request object.
        wallet.client().setRequireEncryptedRequest(false);
        try {
            performSameDeviceLogin("get-request-user");
            flow.assertLoginSucceeded();

            ActivityLogEntry fetch = requestObjectFetch();
            assertThat(fetch.details()).containsEntry("method", "GET");
        } finally {
            wallet.client().resetConformance();
        }
    }

    private ActivityLogEntry requestObjectFetch() {
        return wallet.client().getActivityLog().stream()
                .filter(entry ->
                        "request_object_fetch_response".equals(entry.details().get("event")))
                .findFirst()
                .orElseThrow();
    }
}
