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
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustListProviderTest {

    private ECKey signingKey;
    private ECDSASigner signer;

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
    void parseTrustListJwt_withExp_usesExpAsExpiry() throws Exception {
        Instant exp = Instant.now().plusSeconds(600);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(exp))
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt().getEpochSecond()).isEqualTo(exp.getEpochSecond());
    }

    @Test
    void parseTrustListJwt_withoutExp_expiresImmediately() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());
        Instant before = Instant.now();

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt()).isBetween(before.minusSeconds(1), before.plusSeconds(1));
    }

    @Test
    void parseTrustListJwt_emptyEntitiesList_returnsEmptyKeys() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.certificates()).isEmpty();
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

    @Nested
    class StaleCacheFallback {

        private static final String TEST_URL = "https://stale-test.example.com/tl.jwt";

        @Test
        void fetchFailure_withRecentStaleEntry_returnsStaleCertificates() throws Exception {
            X509Certificate cert = generateTestCert();

            // Seed cache: expired 10 seconds ago, fetched 30 seconds ago
            TrustListProvider.seedExpiredCache(
                    TEST_URL,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(30));

            // No session → fetch will fail, but stale entry is within default maxStaleAge (1 day)
            TrustListProvider provider =
                    new TrustListProvider(null, TEST_URL, null, null, (List<X509Certificate>) null);

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).containsExactly(cert);
        }

        @Test
        void fetchFailure_withStaleEntryBeyondMaxAge_returnsEmpty() throws Exception {
            X509Certificate cert = generateTestCert();

            // Seed cache: fetched 2 hours ago
            TrustListProvider.seedExpiredCache(
                    TEST_URL,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(7200));

            // maxStaleAge = 1 hour, but entry was fetched 2 hours ago → too old
            TrustListProvider provider =
                    new TrustListProvider(null, TEST_URL, null, Duration.ofHours(1), (List<X509Certificate>) null);

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }

        @Test
        void fetchFailure_withMaxStaleAgeZero_returnsEmpty() throws Exception {
            X509Certificate cert = generateTestCert();

            // Seed cache: recently fetched
            TrustListProvider.seedExpiredCache(
                    TEST_URL,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(5));

            // maxStaleAge = ZERO disables stale cache entirely
            TrustListProvider provider =
                    new TrustListProvider(null, TEST_URL, null, Duration.ZERO, (List<X509Certificate>) null);

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }

        @Test
        void fetchFailure_withStaleEntryWithinCustomMaxAge_returnsStaleCertificates() throws Exception {
            X509Certificate cert = generateTestCert();

            // Seed cache: fetched 5 minutes ago
            TrustListProvider.seedExpiredCache(
                    TEST_URL,
                    List.of(cert),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(300));

            // maxStaleAge = 10 minutes → 5-minute-old entry is within range
            TrustListProvider provider =
                    new TrustListProvider(null, TEST_URL, null, Duration.ofMinutes(10), (List<X509Certificate>) null);

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).containsExactly(cert);
        }

        @Test
        void fetchFailure_withEmptyStaleEntry_returnsEmpty() {
            // Seed cache with empty certificate list
            TrustListProvider.seedExpiredCache(
                    TEST_URL,
                    List.of(),
                    Instant.now().minusSeconds(10),
                    Instant.now().minusSeconds(5));

            TrustListProvider provider =
                    new TrustListProvider(null, TEST_URL, null, null, (List<X509Certificate>) null);

            List<X509Certificate> result = provider.getTrustedCertificates();
            assertThat(result).isEmpty();
        }

        private X509Certificate generateTestCert() throws Exception {
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
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
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
            TrustListProvider provider =
                    new TrustListProvider(null, "https://example.com", null, (List<X509Certificate>) null);

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

        private X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            // We need a KeyPair from the ECKey
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
    }

    private String buildSignedJwt(JWTClaimsSet claims) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
