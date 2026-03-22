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

import static org.assertj.core.api.Assertions.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class TrustListProviderTest {

    private static final String PID_ISSUANCE_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String PID_REVOCATION_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Revocation";

    private ECKey signingKey;
    private ECDSASigner signer;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(TrustListProviderTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        signer = new ECDSASigner(signingKey);
    }

    @AfterEach
    void clearCaches() {
        TrustListProvider.clearCache();
    }

    @Test
    void parseTrustListJwt_withNextUpdate_usesNextUpdateAsExpiry() throws Exception {
        Instant nextUpdate = Instant.now().plusSeconds(600);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim(
                        "ListAndSchemeInformation",
                        Map.of(
                                "LoTEType",
                                "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                                "NextUpdate",
                                nextUpdate.toString()))
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt().getEpochSecond()).isEqualTo(nextUpdate.getEpochSecond());
        assertThat(result.loTEType()).isEqualTo("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
    }

    @Test
    void parseTrustListJwt_withNextUpdateAndExp_ignoresExp() throws Exception {
        Instant nextUpdate = Instant.now().plusSeconds(600);
        Instant exp = Instant.now().plusSeconds(300);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(exp))
                .claim(
                        "ListAndSchemeInformation",
                        Map.of(
                                "LoTEType",
                                "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                                "NextUpdate",
                                nextUpdate.toString()))
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt().getEpochSecond()).isEqualTo(nextUpdate.getEpochSecond());
        assertThat(result.loTEType()).isEqualTo("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
    }

    @Test
    void parseTrustListJwt_withoutNextUpdate_hasNoExpiry() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt()).isNull();
    }

    @Test
    void parseTrustListJwt_emptyEntitiesList_returnsEmptyKeys() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.certificates()).isEmpty();
        assertThat(result.issuanceCertificates()).isEmpty();
        assertThat(result.revocationCertificates()).isEmpty();
    }

    @Test
    void parseTrustListJwt_certificatesAreImmutable() throws Exception {
        X509Certificate cert = generateTestCert(true);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim("TrustedEntitiesList", trustListClaims(cert))
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThatThrownBy(() -> result.certificates().add(cert)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void parseTrustListJwt_invalidJwtFormat_throws() {
        assertThatThrownBy(() -> TrustListProvider.parseTrustListJwt("not-a-jwt"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void staticKeys_returnedDirectly() {
        TrustListProvider provider = new TrustListProvider(List.of());
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    @Test
    void nullTrustListUrl_returnsEmptyKeys() {
        TrustListProvider provider = new TrustListProvider(null, null);
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    @Test
    void blankTrustListUrl_returnsEmptyKeys() {
        TrustListProvider provider = new TrustListProvider(null, "  ");
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    @Test
    void defaultMaxStaleAge_isOneDay() {
        assertThat(TrustListProvider.DEFAULT_MAX_STALE_AGE).isEqualTo(Duration.ofDays(1));
    }

    @Test
    void trustedAuthorityKeyIdentifiers_areReadFromCertificateExtensions() throws Exception {
        X509Certificate cert = generateTestCert(true);

        TrustListProvider provider = new TrustListProvider(List.of(cert));

        assertThat(provider.getTrustedAuthorityKeyIdentifiers()).hasSize(1);
        assertThat(provider.getTrustedAuthorityKeyIdentifiers().get(0)).isNotBlank();
    }

    @Test
    void trustedAuthorityKeyIdentifiers_withoutCertificateExtensions_returnsEmpty() throws Exception {
        TrustListProvider provider = new TrustListProvider(List.of(generateTestCert(false)));

        assertThat(provider.getTrustedAuthorityKeyIdentifiers()).isEmpty();
    }

    @Test
    void parseTrustListJwt_separatesIssuanceAndRevocationCertificates() throws Exception {
        X509Certificate issuanceCert = generateTestCert(true);
        X509Certificate revocationCert = generateTestCert(true);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim(
                        "TrustedEntitiesList",
                        trustListClaims(
                                serviceClaim(PID_ISSUANCE_SERVICE_TYPE, issuanceCert),
                                serviceClaim(PID_REVOCATION_SERVICE_TYPE, revocationCert)))
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.certificates()).containsExactly(issuanceCert, revocationCert);
        assertThat(result.issuanceCertificates()).containsExactly(issuanceCert);
        assertThat(result.revocationCertificates()).containsExactly(revocationCert);
    }

    @Test
    void trustedAuthorityKeyIdentifiers_useIssuanceCertificatesOnly() throws Exception {
        X509Certificate issuanceCert = generateTestCert(true);
        X509Certificate revocationCert = generateTestCert(false);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim(
                        "TrustedEntitiesList",
                        trustListClaims(
                                serviceClaim(PID_ISSUANCE_SERVICE_TYPE, issuanceCert),
                                serviceClaim(PID_REVOCATION_SERVICE_TYPE, revocationCert)))
                .build());
        StubTrustListProvider provider = new StubTrustListProvider("https://example.com/tl.jwt", List.of(jwt));

        assertThat(provider.getTrustedAuthorityKeyIdentifiers()).hasSize(1);
    }

    @Nested
    class StaleCacheFallback {

        private static final String TEST_URL = "https://stale-test.example.com/tl.jwt";

        @Test
        void fetchFailure_withRecentStaleEntry_returnsStaleCertificates() throws Exception {
            X509Certificate cert = generateTestCert(true);

            // Seed cache: expired 10 seconds ago, fetched 30 seconds ago
            TrustListProvider provider = new TrustListProvider(null, TEST_URL, null, null, null);
            TrustListProvider.seedExpiredCache(
                    provider,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(30));

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).containsExactly(cert);
        }

        @Test
        void fetchFailure_withStaleEntryBeyondMaxAge_returnsEmpty() throws Exception {
            X509Certificate cert = generateTestCert(true);

            // Seed cache: fetched 2 hours ago
            TrustListProvider provider = new TrustListProvider(null, TEST_URL, null, Duration.ofHours(1), null);
            TrustListProvider.seedExpiredCache(
                    provider,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(7200));

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }

        @Test
        void fetchFailure_withMaxStaleAgeZero_returnsEmpty() throws Exception {
            X509Certificate cert = generateTestCert(true);

            // Seed cache: recently fetched
            TrustListProvider provider = new TrustListProvider(null, TEST_URL, null, Duration.ZERO, null);
            TrustListProvider.seedExpiredCache(
                    provider,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(5));

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }

        @Test
        void fetchFailure_withStaleEntryWithinCustomMaxAge_returnsStaleCertificates() throws Exception {
            X509Certificate cert = generateTestCert(true);

            // Seed cache: fetched 5 minutes ago
            TrustListProvider provider = new TrustListProvider(null, TEST_URL, null, Duration.ofMinutes(10), null);
            TrustListProvider.seedExpiredCache(
                    provider,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(300));

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).containsExactly(cert);
        }

        @Test
        void fetchFailure_withEmptyStaleEntry_returnsEmpty() {
            // Seed cache with empty certificate list
            TrustListProvider provider = new TrustListProvider(null, TEST_URL, null, null, null);
            TrustListProvider.seedExpiredCache(
                    provider,
                    List.of(),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(5));

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }
    }

    @Nested
    class NoExpCaching {

        private static final String TEST_URL = "https://no-exp.example.com/tl.jwt";

        @Test
        void trustListWithoutNextUpdate_isNotCachedOrReusableAsStale() throws Exception {
            X509Certificate cert = generateTestCert(true);
            String jwtWithoutExp = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("TrustedEntitiesList", trustListClaims(cert))
                    .build());
            StubTrustListProvider provider =
                    new StubTrustListProvider(TEST_URL, List.of(jwtWithoutExp, new IllegalStateException("boom")));

            assertThat(provider.getTrustedCertificates()).containsExactly(cert);
            assertThat(provider.getTrustedCertificates()).isEmpty();
        }

        @Test
        void trustListCachesUntilHttpCacheExpiryWhenEarlierThanNextUpdate() throws Exception {
            X509Certificate cert = generateTestCert(true);
            Instant nextUpdate = Instant.now().plusSeconds(600);
            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("ListAndSchemeInformation", Map.of("NextUpdate", nextUpdate.toString()))
                    .claim("TrustedEntitiesList", trustListClaims(cert))
                    .build());
            StubTrustListProvider provider = new StubTrustListProvider(
                    TEST_URL,
                    List.of(
                            new TrustListProvider.FetchedTrustList(
                                    jwt, Instant.now().plusSeconds(60)),
                            new IllegalStateException("boom")));

            assertThat(provider.getTrustedCertificates()).containsExactly(cert);
            assertThat(provider.getTrustedCertificates()).containsExactly(cert);
        }

        @Test
        void trustListWithPastNextUpdate_isDiscarded() throws Exception {
            X509Certificate cert = generateTestCert(true);
            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim(
                            "ListAndSchemeInformation",
                            Map.of("NextUpdate", Instant.now().minusSeconds(30).toString()))
                    .claim("TrustedEntitiesList", trustListClaims(cert))
                    .build());
            StubTrustListProvider provider = new StubTrustListProvider(TEST_URL, List.of(jwt));

            assertThat(provider.getTrustedCertificates()).isEmpty();
        }
    }

    @Nested
    class CacheIsolation {

        private static final String TEST_URL = "https://cache-isolation.example.com/tl.jwt";

        @Test
        void cacheKey_includesSigningCertificateFingerprints() throws Exception {
            X509Certificate cachedCert = generateTestCert(true);
            X509Certificate wrongSigningCert = generateSelfSignedCert(new ECKeyGenerator(Curve.P_256).generate());

            TrustListProvider unsignedProvider = new TrustListProvider(null, TEST_URL, null, null, null);
            TrustListProvider signedProvider =
                    new TrustListProvider(null, TEST_URL, null, null, List.of(wrongSigningCert));

            TrustListProvider.seedExpiredCache(
                    unsignedProvider, List.of(cachedCert), Instant.now().plusSeconds(300), Instant.now());

            assertThat(unsignedProvider.getTrustedCertificates()).containsExactly(cachedCert);
            assertThat(signedProvider.getTrustedCertificates()).isEmpty();
        }

        @Test
        void cacheKey_includesCachePolicy() throws Exception {
            X509Certificate cachedCert = generateTestCert(true);

            TrustListProvider defaultProvider = new TrustListProvider(null, TEST_URL, null, null, null);
            TrustListProvider shortTtlProvider =
                    new TrustListProvider(null, TEST_URL, Duration.ofSeconds(30), null, null);

            TrustListProvider.seedExpiredCache(
                    defaultProvider, List.of(cachedCert), Instant.now().plusSeconds(300), Instant.now());

            assertThat(defaultProvider.getTrustedCertificates()).containsExactly(cachedCert);
            assertThat(shortTtlProvider.getTrustedCertificates()).isEmpty();
        }

        @Test
        void returnedCachedCertificates_areImmutable() throws Exception {
            X509Certificate cert = generateTestCert(true);
            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim(
                            "ListAndSchemeInformation",
                            Map.of("NextUpdate", Instant.now().plusSeconds(600).toString()))
                    .claim("TrustedEntitiesList", trustListClaims(cert))
                    .build());
            StubTrustListProvider provider = new StubTrustListProvider(TEST_URL, List.of(jwt));

            List<X509Certificate> first = provider.getTrustedCertificates();

            assertThatThrownBy(() -> first.add(cert)).isInstanceOf(UnsupportedOperationException.class);
            assertThat(provider.getTrustedCertificates()).containsExactly(cert);
        }
    }

    @Nested
    class SignatureVerification {

        @Test
        void verifySignature_withMatchingCert_succeeds() throws Exception {
            X509Certificate cert = generateSelfSignedCert(signingKey);
            TrustListProvider provider = new TrustListProvider(null, "https://example.com", null, List.of(cert));

            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("TrustedEntitiesList", List.of())
                    .build());

            assertThatCode(() -> provider.verifySignature(jwt)).doesNotThrowAnyException();
        }

        @Test
        void verifySignature_withWrongCert_throws() throws Exception {
            ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
            X509Certificate wrongCert = generateSelfSignedCert(otherKey);
            TrustListProvider provider = new TrustListProvider(null, "https://example.com", null, List.of(wrongCert));

            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("TrustedEntitiesList", List.of())
                    .build());

            assertThatThrownBy(() -> provider.verifySignature(jwt))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("signature verification failed");
        }

        @Test
        void verifySignature_withNoCert_skipsVerification() throws Exception {
            TrustListProvider provider = new TrustListProvider(null, "https://example.com", null, null);

            // Sign with any key — verification should be skipped
            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("TrustedEntitiesList", List.of())
                    .build());

            assertThatCode(() -> provider.verifySignature(jwt)).doesNotThrowAnyException();
        }

        @Test
        void verifySignature_withMultipleCerts_matchesSecond() throws Exception {
            ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
            X509Certificate wrongCert = generateSelfSignedCert(otherKey);
            X509Certificate correctCert = generateSelfSignedCert(signingKey);
            TrustListProvider provider =
                    new TrustListProvider(null, "https://example.com", null, List.of(wrongCert, correctCert));

            String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                    .claim("TrustedEntitiesList", List.of())
                    .build());

            assertThatCode(() -> provider.verifySignature(jwt)).doesNotThrowAnyException();
        }
    }

    private String buildSignedJwt(JWTClaimsSet claims) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = new KeyPair(ecKey.toECPublicKey(), ecKey.toECPrivateKey());

        X500Principal subject = new X500Principal("CN=TrustList Signer");
        Instant now = Instant.now();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(3600)),
                Date.from(now.plusSeconds(86400)),
                subject,
                kp.getPublic());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    private static X509Certificate generateTestCert(boolean includeSubjectKeyIdentifier) throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        KeyPair kp = new KeyPair(key.toECPublicKey(), key.toECPrivateKey());
        X500Principal subject = new X500Principal("CN=Test Issuer");
        Instant now = Instant.now();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(3600)),
                Date.from(now.plusSeconds(86400)),
                subject,
                kp.getPublic());
        if (includeSubjectKeyIdentifier) {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            certBuilder.addExtension(
                    Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(kp.getPublic()));
        }
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    private static List<Map<String, Object>> trustListClaims(X509Certificate cert) throws Exception {
        return trustListClaims(serviceClaim(PID_ISSUANCE_SERVICE_TYPE, cert));
    }

    @SafeVarargs
    private static List<Map<String, Object>> trustListClaims(Map<String, Object>... services) {
        return List.of(Map.of("TrustedEntityServices", List.of(services)));
    }

    private static Map<String, Object> serviceClaim(String serviceTypeIdentifier, X509Certificate cert)
            throws Exception {
        return Map.of(
                "ServiceInformation",
                Map.of(
                        "ServiceTypeIdentifier",
                        serviceTypeIdentifier,
                        "ServiceDigitalIdentity",
                        Map.of(
                                "X509Certificates",
                                List.of(Map.of("val", Base64.getMimeEncoder().encodeToString(cert.getEncoded()))))));
    }

    private static final class StubTrustListProvider extends TrustListProvider {
        private final ArrayDeque<Object> responses;

        private StubTrustListProvider(String trustListUrl, List<Object> responses) {
            super(null, trustListUrl, null, null, null);
            this.responses = new ArrayDeque<>(responses);
        }

        @Override
        void verifySignature(String jwt) {}

        @Override
        protected FetchedTrustList fetchTrustListJwt() throws Exception {
            Object next = responses.removeFirst();
            if (next instanceof Exception exception) {
                throw exception;
            }
            if (next instanceof FetchedTrustList fetchedTrustList) {
                return fetchedTrustList;
            }
            return new FetchedTrustList(next.toString(), null);
        }
    }
}
