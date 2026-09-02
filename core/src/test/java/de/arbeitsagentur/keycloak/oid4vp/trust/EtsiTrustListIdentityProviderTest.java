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
package de.arbeitsagentur.keycloak.oid4vp.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthorityType;
import de.arbeitsagentur.keycloak.oid4vp.verification.TrustListProvider;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.crypto.CryptoIntegration;

class EtsiTrustListIdentityProviderTest {

    private static final TrustMaterialRequest EMPTY_REQUEST =
            TrustMaterialRequest.builder().build();

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(EtsiTrustListIdentityProviderTest.class.getClassLoader());
    }

    @Test
    void staticPemModePartitionsCaAnchorsAndEndEntityCertificates() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=Static CA", "CN=Static CA", true);
        KeyPair eeKp = generateKeyPair();
        X509Certificate endEntity = generateCert(eeKp, caKp, "CN=Static Issuer", "CN=Static CA", false);

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustedCertificates(toPem(ca) + toPem(endEntity));
        config.setRequiredExtendedKeyUsages("1.0.18013.5.1.2");
        config.setAdvertisedTrustedAuthorityType("aki");
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(null, config);

        List<X509TrustMaterial> materials =
                provider.resolveX509Trust(EMPTY_REQUEST).toList();
        assertThat(materials).hasSize(1);
        assertThat(materials.get(0).trustAnchors()).containsExactly(ca);
        assertThat(materials.get(0).requiredExtendedKeyUsages()).containsExactly("1.0.18013.5.1.2");

        assertThat(provider.resolveKeys(EMPTY_REQUEST)).isEmpty();
        assertThat(provider.directIssuerCertificates())
                .as("the CA certificate is a trust anchor, only the end entity certificate is trusted directly")
                .containsExactly(endEntity);
        assertThat(provider.revocationCertificates()).containsExactly(ca, endEntity);
        assertThat(provider.trustedAuthorities())
                .as("a pasted bundle without key identifiers has nothing to advertise")
                .isEmpty();
    }

    @Test
    void endEntityOnlyBundleExposesNoX509TrustMaterial() throws Exception {
        KeyPair caKp = generateKeyPair();
        KeyPair eeKp = generateKeyPair();
        X509Certificate endEntity = generateCert(eeKp, caKp, "CN=Pinned Issuer", "CN=External CA", false);

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustedCertificates(toPem(endEntity));
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(null, config);

        assertThat(provider.resolveX509Trust(EMPTY_REQUEST)).isEmpty();
        assertThat(provider.directIssuerCertificates()).containsExactly(endEntity);
    }

    @Test
    void trustListModeEnforcesExpectedLoTEType() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=TL CA", "CN=TL CA", true);

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.setTrustListLoTEType("http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList");
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(
                config, new FixedTrustListProvider(List.of(ca), "http://uri.etsi.org/19602/LoTEType/Other"), null);

        assertThatThrownBy(() -> provider.resolveX509Trust(EMPTY_REQUEST))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("LoTE type mismatch");
    }

    @Test
    void trustListModeExposesMatchingLoTETrust() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=TL CA", "CN=TL CA", true);
        String expected = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList";

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.setTrustListLoTEType(expected);
        config.setAdvertisedTrustedAuthorityType("etsi_tl");
        EtsiTrustListIdentityProvider provider =
                new EtsiTrustListIdentityProvider(config, new FixedTrustListProvider(List.of(ca), expected), null);

        List<X509TrustMaterial> materials =
                provider.resolveX509Trust(EMPTY_REQUEST).toList();
        assertThat(materials).hasSize(1);
        assertThat(materials.get(0).trustAnchors()).containsExactly(ca);
        assertThat(provider.trustedAuthorities())
                .contains(new TrustedAuthority(TrustedAuthorityType.ETSI_TL, List.of("https://tl.example/list.jwt")));
    }

    @Test
    void configValidationRequiresTrustListUrlOrCertificates() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();

        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trust list URL or trusted certificates");
    }

    @Test
    void configValidationRejectsUnparsablePem() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustedCertificates("not a pem bundle");

        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PEM bundle");
    }

    @Test
    void combinesTrustListAndPastedCertificates() throws Exception {
        KeyPair tlCaKp = generateKeyPair();
        X509Certificate tlCa = generateCert(tlCaKp, tlCaKp, "CN=TL CA", "CN=TL CA", true);
        KeyPair staticCaKp = generateKeyPair();
        X509Certificate staticCa = generateCert(staticCaKp, staticCaKp, "CN=Static CA", "CN=Static CA", true);

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(
                config, new FixedTrustListProvider(List.of(tlCa), null), new TrustListProvider(List.of(staticCa)));

        List<X509TrustMaterial> materials =
                provider.resolveX509Trust(EMPTY_REQUEST).toList();
        assertThat(materials).hasSize(1);
        assertThat(materials.get(0).trustAnchors()).containsExactlyInAnyOrder(tlCa, staticCa);
        assertThat(provider.revocationCertificates()).containsExactly(tlCa, staticCa);
        assertThat(provider.directIssuerCertificates())
                .as("both sources contribute CA certificates only, which are anchors rather than direct issuer certs")
                .isEmpty();
    }

    @Test
    void exposesAuthorityKeyIdentifiersOfStaticAnchors() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCertWithSki(caKp, "CN=SKI CA");

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustedCertificates(toPem(ca));
        config.setAdvertisedTrustedAuthorityType("aki");
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(null, config);

        assertThat(provider.trustedAuthorities()).hasSize(1);
        assertThat(provider.trustedAuthorities().get(0).type()).isEqualTo(TrustedAuthorityType.AKI);
        assertThat(provider.trustedAuthorities().get(0).values()).hasSize(1);
    }

    @Test
    void advertisesAuthorityKeyIdentifiersOfAFreshlyPulledTrustList() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCertWithSki(caKp, "CN=SKI CA");

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.setAdvertisedTrustedAuthorityType("aki");
        EtsiTrustListIdentityProvider provider =
                new EtsiTrustListIdentityProvider(config, new FixedTrustListProvider(List.of(ca), null), null);

        assertThat(provider.trustedAuthorities())
                .as("the aki entries do not depend on an earlier verification having warmed a cache")
                .anyMatch(authority -> authority.type() == TrustedAuthorityType.AKI
                        && authority.values().size() == 1);
    }

    @Test
    void advertisesOneEntryOfTheConfiguredType() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCertWithSki(caKp, "CN=SKI CA");

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.setAdvertisedTrustedAuthorityType("aki");
        EtsiTrustListIdentityProvider provider =
                new EtsiTrustListIdentityProvider(config, new FixedTrustListProvider(List.of(ca), null), null);

        assertThat(provider.trustedAuthorities())
                .as("the trust list url stays out of the request when aki is advertised")
                .allMatch(authority -> authority.type() == TrustedAuthorityType.AKI)
                .isNotEmpty();

        config.setAdvertisedTrustedAuthorityType("etsi_tl");
        assertThat(provider.trustedAuthorities())
                .allMatch(authority -> authority.type() == TrustedAuthorityType.ETSI_TL)
                .isNotEmpty();
    }

    @Test
    void advertisesNothingByDefault() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCertWithSki(caKp, "CN=SKI CA");

        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        EtsiTrustListIdentityProvider provider =
                new EtsiTrustListIdentityProvider(config, new FixedTrustListProvider(List.of(ca), null), null);

        assertThat(provider.trustedAuthorities())
                .as("without a configured type the DCQL query carries no trusted_authorities")
                .isEmpty();
    }

    @Test
    void rejectsAnythingButOneAdvertisedTrustedAuthorityType() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");

        config.setAdvertisedTrustedAuthorityType("openid_federation");
        assertThatThrownBy(config::getAdvertisedTrustedAuthorityType)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("openid_federation");

        config.setAdvertisedTrustedAuthorityType("aki,etsi_tl");
        assertThatThrownBy(config::getAdvertisedTrustedAuthorityType)
                .as("both types describe the same anchors, so advertising both makes no sense")
                .isInstanceOf(IllegalArgumentException.class);

        config.setAdvertisedTrustedAuthorityType("true");
        assertThatThrownBy(config::getAdvertisedTrustedAuthorityType)
                .as("the boolean values of earlier releases are gone, blank means the default")
                .isInstanceOf(IllegalArgumentException.class);

        config.setAdvertisedTrustedAuthorityType("false");
        assertThatThrownBy(config::getAdvertisedTrustedAuthorityType).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAdvertisingTheTrustListWithoutATrustListUrl() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setAdvertisedTrustedAuthorityType("etsi_tl");

        assertThatThrownBy(config::getAdvertisedTrustedAuthorityType)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trust list URL");
    }

    @Test
    void servesEveryCredentialTypeUntilTypesAreDeclared() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(config, null, null);

        assertThat(provider.servedCredentialTypes()).isEmpty();

        config.setServedCredentialTypes(" urn:eudi:pid:1 , org.iso.18013.5.1.mDL ");
        assertThat(provider.servedCredentialTypes()).containsExactly("urn:eudi:pid:1", "org.iso.18013.5.1.mDL");
    }

    @Test
    void trustListIsPulledOncePerProviderInstance() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCertWithSki(caKp, "CN=SKI CA");
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        CountingTrustListProvider trustList = new CountingTrustListProvider(List.of(ca));
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(config, trustList, null);

        resolveAllTrustMaterial(provider);
        int issuancePullsOfFirstResolution = trustList.issuancePulls;
        int revocationPullsOfFirstResolution = trustList.revocationPulls;

        resolveAllTrustMaterial(provider);
        resolveAllTrustMaterial(provider);

        assertThat(trustList.issuancePulls)
                .as("a trust list without freshness metadata would otherwise be fetched for every ask")
                .isEqualTo(issuancePullsOfFirstResolution);
        assertThat(trustList.revocationPulls).isEqualTo(revocationPullsOfFirstResolution);
    }

    private static void resolveAllTrustMaterial(EtsiTrustListIdentityProvider provider) {
        provider.resolveX509Trust(EMPTY_REQUEST).toList();
        provider.directIssuerCertificates();
        provider.revocationCertificates();
        provider.trustedAuthorities();
    }

    @Test
    void aFailingTrustListIsNotMemoizedAsEmpty() {
        EtsiTrustListIdentityProviderConfig config = new EtsiTrustListIdentityProviderConfig();
        config.setTrustListUrl("https://tl.example/list.jwt");
        FailingTrustListProvider trustList = new FailingTrustListProvider();
        EtsiTrustListIdentityProvider provider = new EtsiTrustListIdentityProvider(config, trustList, null);

        assertThatThrownBy(provider::directIssuerCertificates).isInstanceOf(IdentityBrokerException.class);
        assertThatThrownBy(provider::directIssuerCertificates)
                .as("a resolution that failed must not leave the provider believing the trust list is empty")
                .isInstanceOf(IdentityBrokerException.class);
        assertThat(trustList.pulls).isEqualTo(2);
    }

    private static class CountingTrustListProvider extends TrustListProvider {

        private final List<X509Certificate> certificates;
        private int issuancePulls;
        private int revocationPulls;

        CountingTrustListProvider(List<X509Certificate> certificates) {
            super(certificates);
            this.certificates = certificates;
        }

        @Override
        public List<X509Certificate> getIssuanceCertificates() {
            issuancePulls++;
            return certificates;
        }

        @Override
        public List<X509Certificate> getRevocationCertificates() {
            revocationPulls++;
            return certificates;
        }
    }

    private static class FailingTrustListProvider extends TrustListProvider {

        private int pulls;

        FailingTrustListProvider() {
            super(List.of());
        }

        @Override
        public List<X509Certificate> getIssuanceCertificates() {
            pulls++;
            throw new IdentityBrokerException("Trust list unreachable");
        }
    }

    private static class FixedTrustListProvider extends TrustListProvider {

        private final List<X509Certificate> certificates;
        private final String loTEType;

        FixedTrustListProvider(List<X509Certificate> certificates, String loTEType) {
            super(certificates);
            this.certificates = certificates;
            this.loTEType = loTEType;
        }

        @Override
        public List<X509Certificate> getIssuanceCertificates() {
            return certificates;
        }

        @Override
        public List<X509Certificate> getRevocationCertificates() {
            return certificates;
        }

        @Override
        public String getCurrentLoTEType() {
            return loTEType;
        }
    }

    private static String toPem(X509Certificate certificate) throws Exception {
        StringWriter writer = new StringWriter();
        writer.write("-----BEGIN CERTIFICATE-----\n");
        writer.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()));
        writer.write("\n-----END CERTIFICATE-----\n");
        return writer.toString();
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp, KeyPair issuerKp, String subjectDn, String issuerDn, boolean isCa) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli() + System.nanoTime() % 1000),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static X509Certificate generateCertWithSki(KeyPair keyPair, String dn) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(dn),
                BigInteger.valueOf(Instant.now().toEpochMilli() + System.nanoTime() % 1000),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(dn),
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
