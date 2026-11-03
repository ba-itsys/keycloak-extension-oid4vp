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

import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCrlServer;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestTrustListServer;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import io.github.dominikschlosser.eudi.CredentialCertificate;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.PemUtils;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * End to end coverage of how CRLs reach the verifier. A {@code crlEndpoint} that serves bytes no CRL
 * parser accepts tests the download itself, and the wallet's own CRL endpoints test real revocation.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpCrlE2eIT extends AbstractOid4vpE2eTest {

    private static final byte[] NOT_A_CRL = {1, 2, 3};
    private static final Duration REFRESH_TIMEOUT = Duration.ofSeconds(10);

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void loginsDownloadTheCrl() throws Exception {
        try (TestTrustListServer trustList = rootCaTrustList();
                TestCrlServer crl = new TestCrlServer(NOT_A_CRL)) {
            setTrustIdpConfig(Map.of(
                    EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                    trustList.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT,
                    crl.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_MAX_CACHE_TTL_SECONDS,
                    "0"));

            login("crl-first-download");
            flow.assertLoginSucceeded();
            awaitDownloads(crl, 1);

            login("crl-refresh");
            flow.assertLoginSucceeded();
            awaitDownloads(crl, 2);
        }
    }

    @Test
    void failedCrlFetchLetsTheLoginPassAndIsCached() throws Exception {
        try (TestTrustListServer trustList = rootCaTrustList();
                TestCrlServer crl = new TestCrlServer(NOT_A_CRL)) {
            setTrustIdpConfig(Map.of(
                    EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                    trustList.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT,
                    crl.url()));

            login("crl-failed-fetch");
            flow.assertLoginSucceeded();
            awaitDownloads(crl, 1);

            login("crl-cached-failure");
            flow.assertLoginSucceeded();
            assertThat(crl.downloads()).isEqualTo(1);
        }
    }

    @Test
    void requiredCrlRejectsTheLoginWhenNoneIsAvailable() throws Exception {
        try (TestTrustListServer trustList = rootCaTrustList();
                TestCrlServer crl = new TestCrlServer(NOT_A_CRL)) {
            setTrustIdpConfig(Map.of(
                    EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                    trustList.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT,
                    crl.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_REQUIRED,
                    "true"));

            reset();
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            var walletResponse = flow.submitToWallet(flow.getSameDeviceWalletUrl());

            assertLoginFailed(walletResponse, "no crl is available");
        }
    }

    @Test
    void revokedSigningCertificateIsRejected() throws Exception {
        try (TestTrustListServer trustList = rootCaTrustList()) {
            CredentialCertificate signer = signingCertificate();
            String crlPath =
                    wallet.client().revokeCertificate(signer.certificate()).crlPath();
            try {
                setTrustIdpConfig(Map.of(
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                        trustList.url(),
                        EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT,
                        walletCrlEndpoint(crlPath, "revoked")));

                reset();
                flow.navigateToLoginPage();
                flow.clickOid4vpIdpButton();
                var walletResponse = flow.submitToWallet(flow.getSameDeviceWalletUrl());

                assertLoginFailed(walletResponse, "issuer certificate has been revoked");
            } finally {
                wallet.client().undoCertificateRevocation(signer.serial());
            }
        }
    }

    @Test
    void hangingCrlEndpointLetsTheLoginPassAfterTheBoundedWait() throws Exception {
        try (TestTrustListServer trustList = rootCaTrustList();
                TestCrlServer crl = TestCrlServer.hanging()) {
            setTrustIdpConfig(Map.of(
                    EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                    trustList.url(),
                    EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT,
                    crl.url()));

            login("crl-hanging-endpoint");

            flow.assertLoginSucceeded();
            assertThat(crl.downloads()).isEqualTo(1);
        }
    }

    private CredentialCertificate signingCertificate() {
        return wallet.client()
                .getCredentialCertificates(
                        wallet.client().getCredentials().get(0).id())
                .get(0);
    }

    // Adds a query to keep the test apart, because CRLs stay cached in Keycloak across the tests of a class.
    private String walletCrlEndpoint(String crlPath, String test) {
        return wallet.baseUrl() + crlPath + "?test=" + test;
    }

    // Uses the root CA, because the default trust list pins the wallet's signing certificate and
    // pinned certificates skip CRL checks.
    private TestTrustListServer rootCaTrustList() {
        return TestTrustListServer.serving(
                PemUtils.decodeCertificate(wallet.client().getCaCertificatePem()));
    }

    private void login(String usernamePrefix) throws Exception {
        reset();
        performSameDeviceLogin(usernamePrefix);
    }

    private void reset() {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
    }

    private static void awaitDownloads(TestCrlServer crl, int expected) throws Exception {
        long deadline = System.nanoTime() + REFRESH_TIMEOUT.toNanos();
        while (crl.downloads() < expected) {
            if (System.nanoTime() > deadline) {
                throw new TimeoutException("Keycloak did not refresh the CRL in the background");
            }
            Thread.sleep(50);
        }
    }
}
