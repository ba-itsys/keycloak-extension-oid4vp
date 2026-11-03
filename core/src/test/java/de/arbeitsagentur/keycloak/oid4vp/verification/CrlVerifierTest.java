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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.arbeitsagentur.keycloak.oid4vp.trust.CrlPolicy;
import de.arbeitsagentur.keycloak.oid4vp.trust.IssuerTrustAnchors;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.trust.TestTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TrustedIssuerCertificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionTask;

class CrlVerifierTest {

    private static final String LEAF_CRL = "https://ca.example/leaf.crl";
    private static final String MIRROR_CRL = "https://mirror.example/leaf.crl";
    private static final String INTERMEDIATE_CRL = "https://root.example/intermediate.crl";
    private static final String FIXED_CRL = "https://proxy.example/fixed.crl";
    private static final String ROOT_DN = "CN=Root CA";
    private static final String CA_DN = "CN=Issuing CA";
    private static final Duration ONE_HOUR = Duration.ofHours(1);
    private static final Duration ONE_DAY = Duration.ofDays(1);

    private KeyPair rootKeys;
    private KeyPair caKeys;
    private X509Certificate root;
    private X509Certificate ca;
    private X509Certificate leaf;
    private ResolvedTrust trust;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(CrlVerifierTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        rootKeys = TestCertificates.generateKeyPair();
        caKeys = TestCertificates.generateKeyPair();
        root = TestCertificates.issue(rootKeys, rootKeys, ROOT_DN, ROOT_DN, true);
        ca = TestCertificates.issue(caKeys, rootKeys, CA_DN, ROOT_DN, true, List.of(INTERMEDIATE_CRL));
        leaf = issueLeaf(LEAF_CRL);
        trust = TestTrust.ofCertificates(root);
    }

    private X509Certificate issueLeaf(String... crlUrls) throws Exception {
        return TestCertificates.issue(
                TestCertificates.generateKeyPair(), caKeys, "CN=Issuer", CA_DN, false, List.of(crlUrls));
    }

    private static Instant inOneDay() {
        return Instant.now().plus(ONE_DAY);
    }

    private static ResolvedTrust domains(IssuerTrustAnchors... domains) {
        return new ResolvedTrust(List.of(domains), List.of(), List.of(), List.of(), List.of(), true);
    }

    /**
     * The CRL servers and background tasks of one test. Each fixture uses provider ids of its own,
     * because the verifier keeps its caches per provider for the lifetime of the JVM.
     */
    private final class Crls {

        private final String providerPrefix = UUID.randomUUID() + "-";
        private final Map<String, byte[]> served = new HashMap<>();
        private final List<String> fetched = new ArrayList<>();
        private final List<Runnable> background = new ArrayList<>();
        private boolean runtimeFailure;
        private boolean downloadDuringTheWait;
        private boolean rejectBackgroundTasks;
        private boolean downloadOnAnotherThread;

        Crls() throws Exception {
            served.put(INTERMEDIATE_CRL, TestCertificates.crl(rootKeys, ROOT_DN, inOneDay()));
        }

        CrlVerifier verifier() {
            return verifier(null, ONE_HOUR);
        }

        CrlVerifier verifier(String fixedEndpoint, Duration maxCacheTtl) {
            return verifier(fixedEndpoint, maxCacheTtl, false);
        }

        CrlVerifier verifier(String fixedEndpoint, Duration maxCacheTtl, boolean required) {
            CrlPolicy policy = new CrlPolicy(providerPrefix + "provider", fixedEndpoint, maxCacheTtl, required);
            CrlVerifier fake = fakeVerifier();
            return new CrlVerifier(null) {
                @Override
                public void check(List<X509Certificate> chain, ResolvedTrust trust) throws VerificationException {
                    fake.check(
                            chain,
                            new ResolvedTrust(
                                    trust.issuerTrustAnchors().stream()
                                            .map(domain -> new IssuerTrustAnchors(
                                                    domain.trustAnchors(), domain.requiredExtendedKeyUsages(), policy))
                                            .toList(),
                                    trust.directIssuerCertificates(),
                                    trust.trustedIssuerKeys(),
                                    trust.revocationCertificates(),
                                    trust.trustedAuthorities(),
                                    trust.hasDeclaredTrustSource()));
                }
            };
        }

        CrlVerifier fakeVerifier() {
            return new CrlVerifier(null) {
                @Override
                byte[] fetchCrl(KeycloakSession session, String url) throws IOException {
                    fetched.add(url);
                    if (runtimeFailure) {
                        throw new IllegalArgumentException("Illegal character in URL");
                    }
                    byte[] crl = served.get(url);
                    if (crl == null) {
                        throw new IOException("HTTP 503");
                    }
                    return crl;
                }

                @Override
                void runInBackground(KeycloakSessionTask task, Runnable done) {
                    if (rejectBackgroundTasks) {
                        throw new RejectedExecutionException("Executor shut down");
                    }
                    Runnable refresh = () -> {
                        task.run(null);
                        done.run();
                    };
                    if (downloadOnAnotherThread) {
                        new Thread(refresh).start();
                    } else if (downloadDuringTheWait) {
                        refresh.run();
                    } else {
                        background.add(refresh);
                    }
                }

                @Override
                Duration firstFetchWait() {
                    return downloadOnAnotherThread ? Duration.ofSeconds(5) : Duration.ZERO;
                }
            };
        }

        void runBackgroundTasks() {
            List<Runnable> tasks = List.copyOf(background);
            background.clear();
            tasks.forEach(Runnable::run);
        }

        // The first check of a CRL finds nothing and leaves the download to a background task.
        void checkLoaded(CrlVerifier verifier, List<X509Certificate> chain, ResolvedTrust trust)
                throws VerificationException {
            verifier.check(chain, trust);
            runBackgroundTasks();
            verifier.check(chain, trust);
        }

        void assertRevoked(CrlVerifier verifier, List<X509Certificate> chain, ResolvedTrust trust) {
            assertThatThrownBy(() -> checkLoaded(verifier, chain, trust))
                    .isInstanceOf(VerificationException.class)
                    .hasMessageContaining("revoked");
        }

        IssuerTrustAnchors domain(String providerId, String fixedEndpoint, X509Certificate anchor) {
            return new IssuerTrustAnchors(
                    Set.of(anchor),
                    List.of(),
                    new CrlPolicy(providerPrefix + providerId, fixedEndpoint, ONE_HOUR, false));
        }
    }

    @Test
    void firstLoginWaitsForTheDownload() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        crls.downloadOnAnotherThread = true;

        assertThatThrownBy(() -> crls.verifier().check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    @Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void waitIsBounded() {
        CrlVerifier verifier = new CrlVerifier(null) {
            @Override
            void runInBackground(KeycloakSessionTask task, Runnable done) {}

            @Override
            Duration firstFetchWait() {
                return Duration.ofMillis(50);
            }
        };

        assertThatCode(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void requiredCrlRejectsWithoutAKnownCrl() throws Exception {
        Crls crls = new Crls();
        assertThatThrownBy(() -> crls.verifier(null, ONE_HOUR, true).check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);
    }

    @Test
    void requiredCrlRejectsAfterAFailedDownload() throws Exception {
        Crls crls = new Crls();
        crls.downloadDuringTheWait = true;
        CrlVerifier verifier = crls.verifier(null, ONE_HOUR, true);

        assertThatThrownBy(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);
        assertThatThrownBy(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);
    }

    @Test
    void requiredCrlDownloadsAgainInsteadOfRejectingOnACachedFailure() throws Exception {
        Crls crls = new Crls();
        crls.downloadDuringTheWait = true;
        CrlVerifier verifier = crls.verifier(null, ONE_HOUR, true);
        assertThatThrownBy(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);

        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        assertThatCode(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void cachedFailureCausesNoDownloadWithoutRequiredCrl() throws Exception {
        Crls crls = new Crls();
        crls.downloadDuringTheWait = true;
        CrlVerifier verifier = crls.verifier();
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));

        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).containsExactly(LEAF_CRL);
    }

    @Test
    void requiredCrlAcceptsALastKnownCrl() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.downloadDuringTheWait = true;
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO, true);
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.remove(LEAF_CRL);

        assertThatCode(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void requiredCrlRejectsACertificateWithOnlyLdapDistributionPoints() throws Exception {
        Crls crls = new Crls();
        X509Certificate ldapOnly = issueLeaf("ldap://ca.example/cn=crl");

        assertThatThrownBy(() ->
                        crls.verifier(null, ONE_HOUR, true).check(List.of(ldapOnly), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);
    }

    @Test
    void requiredCrlRejectsACertificateWithoutAUriDistributionPoint() throws Exception {
        Crls crls = new Crls();
        X509Certificate directoryOnly = TestCertificates.issueWithDirectoryNameDistributionPoint(
                TestCertificates.generateKeyPair(), caKeys, "CN=Issuer", CA_DN, "CN=CRL Directory");

        assertThatThrownBy(() ->
                        crls.verifier(null, ONE_HOUR, true).check(List.of(directoryOnly), TestTrust.ofCertificates(ca)))
                .isInstanceOf(RevocationStatusUnavailableException.class);
    }

    @Test
    void requiredCrlAcceptsACertificateWithoutDistributionPoints() throws Exception {
        Crls crls = new Crls();
        X509Certificate withoutCrl = issueLeaf();

        assertThatCode(() ->
                        crls.verifier(null, ONE_HOUR, true).check(List.of(withoutCrl), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void firstLoginGoesOnWhenTheDownloadExceedsTheWait() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier();

        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).isEmpty();
        assertThat(crls.background).hasSize(1);
    }

    @Test
    void laterLoginsUseTheDownloadedCrl() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));

        crls.assertRevoked(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void providersSharingACaEachDownloadTheCrl() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        CrlVerifier verifier = crls.fakeVerifier();

        crls.checkLoaded(verifier, List.of(leaf), domains(crls.domain("provider-a", null, ca)));
        crls.checkLoaded(verifier, List.of(leaf), domains(crls.domain("provider-b", null, ca)));

        assertThat(crls.fetched).containsExactly(LEAF_CRL, LEAF_CRL);
    }

    @Test
    void fixedEndpointOfAnotherProviderDoesNotApply() throws Exception {
        Crls crls = new Crls();
        KeyPair otherKeys = TestCertificates.generateKeyPair();
        X509Certificate otherCa = TestCertificates.issue(otherKeys, otherKeys, "CN=Other CA", "CN=Other CA", true);
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        ResolvedTrust trust =
                domains(crls.domain("provider-a", FIXED_CRL, otherCa), crls.domain("provider-b", null, ca));

        crls.assertRevoked(crls.fakeVerifier(), List.of(leaf), trust);
        assertThat(crls.fetched).containsExactly(LEAF_CRL);
    }

    @Test
    void providerThatRejectsTheChainHasNoSayInItsCrlCheck() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        IssuerTrustAnchors rejecting = new IssuerTrustAnchors(
                Set.of(ca), List.of("1.0.18013.5.1.2"), new CrlPolicy("provider-a", FIXED_CRL, ONE_HOUR, false));
        ResolvedTrust trust = domains(rejecting, crls.domain("provider-b", null, ca));

        crls.assertRevoked(crls.fakeVerifier(), List.of(leaf), trust);
        assertThat(crls.fetched).containsExactly(LEAF_CRL);
    }

    @Test
    void certificatesOutsideTheValidatedPathAreNotFetched() throws Exception {
        Crls crls = new Crls();
        KeyPair attackerKeys = TestCertificates.generateKeyPair();
        X509Certificate attackerCa =
                TestCertificates.issue(attackerKeys, attackerKeys, "CN=Attacker CA", "CN=Attacker CA", true);
        X509Certificate attackerCertificate = TestCertificates.issue(
                TestCertificates.generateKeyPair(),
                attackerKeys,
                "CN=Attacker",
                "CN=Attacker CA",
                false,
                List.of("http://169.254.169.254/latest"));
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        crls.checkLoaded(crls.verifier(), List.of(leaf, ca, attackerCertificate, attackerCa), trust);

        assertThat(crls.fetched).containsExactly(LEAF_CRL, INTERMEDIATE_CRL);
    }

    @Test
    void forgedCopyOfAnIntermediateCannotHideItsRevocation() throws Exception {
        Crls crls = new Crls();
        X509Certificate forged =
                TestCertificates.issue(caKeys, TestCertificates.generateKeyPair(), CA_DN, ROOT_DN, true);
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.served.put(INTERMEDIATE_CRL, TestCertificates.crl(rootKeys, ROOT_DN, inOneDay(), ca));

        crls.assertRevoked(crls.verifier(), List.of(leaf, forged, ca), trust);
    }

    @Test
    void expiredCopyOfAnIntermediateCannotHideItsRevocation() throws Exception {
        Crls crls = new Crls();
        X509Certificate expired = TestCertificates.issueExpired(caKeys, rootKeys, CA_DN, ROOT_DN, true);
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.served.put(INTERMEDIATE_CRL, TestCertificates.crl(rootKeys, ROOT_DN, inOneDay(), ca));

        crls.assertRevoked(crls.verifier(), List.of(leaf, expired, ca), trust);
    }

    @Test
    void runtimeFailureOfTheFetchRejectsNothing() throws Exception {
        Crls crls = new Crls();
        crls.runtimeFailure = true;

        assertThatCode(() -> crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void lastKnownCrlSurvivesAChangedCachePolicy() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        crls.assertRevoked(crls.verifier(null, Duration.ZERO), List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.remove(LEAF_CRL);

        crls.assertRevoked(crls.verifier(null, ONE_HOUR), List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void acceptsCertificateNotOnTheCrl() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        assertThatCode(() -> crls.checkLoaded(crls.verifier(), List.of(leaf, ca), trust))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsRevokedLeaf() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));

        crls.assertRevoked(crls.verifier(), List.of(leaf, ca), trust);
    }

    @Test
    void rejectsRevokedIntermediate() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.served.put(INTERMEDIATE_CRL, TestCertificates.crl(rootKeys, ROOT_DN, inOneDay(), ca));

        crls.assertRevoked(crls.verifier(), List.of(leaf, ca), trust);
    }

    @Test
    void findsIssuerAmongTrustAnchorsWhenChainOmitsIt() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));

        crls.assertRevoked(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void skipsCertificateWithoutHttpDistributionPoint() throws Exception {
        Crls crls = new Crls();
        X509Certificate withoutCrl = issueLeaf();
        X509Certificate ldapOnly = issueLeaf("ldap://ca.example/cn=crl");

        crls.checkLoaded(crls.verifier(), List.of(withoutCrl), TestTrust.ofCertificates(ca));
        crls.checkLoaded(crls.verifier(), List.of(ldapOnly), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).isEmpty();
    }

    @Test
    void skipsTrustAnchorsAndPinnedCertificates() throws Exception {
        Crls crls = new Crls();
        crls.checkLoaded(crls.verifier(), List.of(ca), TestTrust.ofCertificates(ca));
        ResolvedTrust pinned = new ResolvedTrust(
                List.of(crls.domain("provider", null, ca)),
                List.of(new TrustedIssuerCertificate("https://issuer.example", leaf)),
                List.of(),
                List.of(),
                List.of(),
                true);
        crls.checkLoaded(crls.fakeVerifier(), List.of(leaf), pinned);

        assertThat(crls.fetched).isEmpty();
    }

    @Test
    void fixedEndpointReplacesLeafDistributionPoints() throws Exception {
        Crls crls = new Crls();
        crls.served.put(FIXED_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));

        crls.assertRevoked(crls.verifier(FIXED_CRL, ONE_HOUR), List.of(leaf), TestTrust.ofCertificates(ca));
        assertThat(crls.fetched).containsExactly(FIXED_CRL);
    }

    @Test
    void fixedEndpointCoversLeafWithoutDistributionPoints() throws Exception {
        Crls crls = new Crls();
        X509Certificate withoutCrl = issueLeaf();
        crls.served.put(FIXED_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), withoutCrl));

        crls.assertRevoked(crls.verifier(FIXED_CRL, ONE_HOUR), List.of(withoutCrl), TestTrust.ofCertificates(ca));
    }

    @Test
    void fixedEndpointLeavesIntermediateDistributionPoints() throws Exception {
        Crls crls = new Crls();
        crls.served.put(FIXED_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        crls.checkLoaded(crls.verifier(FIXED_CRL, ONE_HOUR), List.of(leaf, ca), trust);

        assertThat(crls.fetched).containsExactly(FIXED_CRL, INTERMEDIATE_CRL);
    }

    @Test
    void cachesCrlUntilTtlEnds() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));
        crls.verifier().check(List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).containsExactly(LEAF_CRL);
        assertThat(crls.background).isEmpty();
    }

    @Test
    void ttlCapsLongNextUpdate() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));

        crls.checkLoaded(crls.verifier(null, Duration.ZERO), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.background).hasSize(1);
    }

    @Test
    void expiredCrlRefreshesWithoutFetchingDuringTheLogin() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.checkLoaded(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.runBackgroundTasks();
        crls.fetched.clear();

        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).isEmpty();
        assertThat(crls.background).hasSize(1);
    }

    @Test
    void backgroundRefreshAppliesToLaterLogins() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.checkLoaded(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void runsOneBackgroundRefreshAtATime() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);

        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));
        assertThat(crls.background).hasSize(1);

        crls.runBackgroundTasks();
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));
        assertThat(crls.background).hasSize(1);
    }

    @Test
    void triesNextDistributionPointWhenOneFails() throws Exception {
        Crls crls = new Crls();
        X509Certificate mirrored = issueLeaf(LEAF_CRL, MIRROR_CRL);
        crls.served.put(MIRROR_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), mirrored));

        crls.assertRevoked(crls.verifier(), List.of(mirrored), TestTrust.ofCertificates(ca));
    }

    @Test
    void failedFetchAcceptsTheCredential() throws Exception {
        Crls crls = new Crls();
        assertThatCode(() -> crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();
    }

    @Test
    void failedFetchIsCachedForTheCacheTtl() throws Exception {
        Crls crls = new Crls();
        CrlVerifier verifier = crls.verifier();

        crls.checkLoaded(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).containsExactly(LEAF_CRL);
        assertThat(crls.background).isEmpty();
    }

    @Test
    void failedRefreshOfAnExpiredCrlIsCachedForTheCacheTtl() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.verifier(null, Duration.ZERO).check(List.of(leaf), TestTrust.ofCertificates(ca));
        crls.runBackgroundTasks();
        crls.served.remove(LEAF_CRL);

        crls.checkLoaded(crls.verifier(null, ONE_HOUR), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.background).isEmpty();
    }

    @Test
    void failedFetchRetriesOnceTheCacheTtlEnds() throws Exception {
        Crls crls = new Crls();
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);

        crls.checkLoaded(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.runBackgroundTasks();

        assertThat(crls.fetched).containsExactly(LEAF_CRL, LEAF_CRL);
    }

    @Test
    void lastKnownCrlKeepsApplyingWhileFetchFails() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.remove(LEAF_CRL);
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void forgedCrlCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(TestCertificates.generateKeyPair(), CA_DN, inOneDay(), leaf));

        crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).contains(LEAF_CRL);
    }

    @Test
    void crlOfAnotherIssuerCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(rootKeys, ROOT_DN, inOneDay(), leaf));

        crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).contains(LEAF_CRL);
    }

    @Test
    void expiredCrlCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(
                LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, Instant.now().minusSeconds(1), leaf));

        crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).contains(LEAF_CRL);
    }

    @Test
    void malformedCrlCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, new byte[] {1, 2, 3});

        crls.checkLoaded(crls.verifier(), List.of(leaf), TestTrust.ofCertificates(ca));

        assertThat(crls.fetched).contains(LEAF_CRL);
    }

    @Test
    void olderCrlDoesNotReplaceTheCachedOne() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(
                LEAF_CRL,
                TestCertificates.crlIssuedAt(caKeys, CA_DN, Instant.now().minus(ONE_HOUR), inOneDay()));
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void deltaCrlCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(
                LEAF_CRL,
                TestCertificates.crlWithExtension(caKeys, CA_DN, inOneDay(), "2.5.29.27", new ASN1Integer(1)));
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void scopedCrlCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(
                LEAF_CRL, TestCertificates.crlWithExtension(caKeys, CA_DN, inOneDay(), "2.5.29.28", new DERSequence()));
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void crlDatedInTheFutureCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(
                LEAF_CRL,
                TestCertificates.crlIssuedAt(
                        caKeys,
                        CA_DN,
                        Instant.now().plus(ONE_DAY),
                        Instant.now().plus(ONE_DAY)));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.checkLoaded(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void crlWithAnUnknownCriticalExtensionCountsAsFailedFetch() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.verifier(null, Duration.ZERO);
        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
        crls.served.put(
                LEAF_CRL,
                TestCertificates.crlWithExtension(caKeys, CA_DN, inOneDay(), "1.2.3.4.5", new ASN1Integer(1)));
        crls.runBackgroundTasks();

        crls.assertRevoked(verifier, List.of(leaf), TestTrust.ofCertificates(ca));
    }

    @Test
    void providerFillingItsCacheKeepsTheCrlsOfOthers() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay(), leaf));
        CrlVerifier verifier = crls.fakeVerifier();
        ResolvedTrust keeper = domains(crls.domain("keeper", null, ca));
        crls.assertRevoked(verifier, List.of(leaf), keeper);

        for (int i = 0; i <= 256; i++) {
            crls.checkLoaded(verifier, List.of(leaf), domains(crls.domain("filler", "http://ca.example/" + i, ca)));
        }
        crls.served.remove(LEAF_CRL);

        crls.assertRevoked(verifier, List.of(leaf), keeper);
    }

    @Test
    void downloadPastItsDeadlineFails() {
        InputStream body = new ByteArrayInputStream(new byte[1]);

        assertThatThrownBy(() -> CrlVerifier.readCrl(body, Instant.now().minusSeconds(1)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("download");
    }

    @Test
    void oversizedDownloadFails() {
        InputStream body = new ByteArrayInputStream(new byte[16 * 1024 * 1024 + 1]);

        assertThatThrownBy(() -> CrlVerifier.readCrl(body, Instant.now().plusSeconds(60)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exceeds");
    }

    @Test
    void refreshThatCannotStartRejectsNothingAndRetries() throws Exception {
        Crls crls = new Crls();
        crls.served.put(LEAF_CRL, TestCertificates.crl(caKeys, CA_DN, inOneDay()));
        crls.rejectBackgroundTasks = true;
        CrlVerifier verifier = crls.verifier();

        assertThatCode(() -> verifier.check(List.of(leaf), TestTrust.ofCertificates(ca)))
                .doesNotThrowAnyException();

        crls.rejectBackgroundTasks = false;
        verifier.check(List.of(leaf), TestTrust.ofCertificates(ca));
        assertThat(crls.background).hasSize(1);
    }
}
