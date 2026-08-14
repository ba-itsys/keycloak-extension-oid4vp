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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import static org.assertj.core.api.Assertions.*;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class Oid4vpClientIdSchemeTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpClientIdSchemeTest.class.getClassLoader());
    }

    @Test
    void resolve_respectsConfiguredPlainScheme() {
        assertThat(Oid4vpClientIdScheme.resolve("plain")).isEqualTo(Oid4vpClientIdScheme.PLAIN);
    }

    @Test
    void resolve_unsetOrUnknownDefaultsToX509Hash() {
        assertThat(Oid4vpClientIdScheme.resolve(null)).isEqualTo(Oid4vpClientIdScheme.X509_HASH);
        assertThat(Oid4vpClientIdScheme.resolve("  ")).isEqualTo(Oid4vpClientIdScheme.X509_HASH);
        assertThat(Oid4vpClientIdScheme.resolve("bogus")).isEqualTo(Oid4vpClientIdScheme.X509_HASH);
    }

    @Test
    void formatValue_usesSpecPrefixForCertificateSchemes() {
        assertThat(Oid4vpClientIdScheme.X509_SAN_DNS.formatValue("test.example.org"))
                .isEqualTo("x509_san_dns:test.example.org");
        assertThat(Oid4vpClientIdScheme.X509_HASH.formatValue("abc123")).isEqualTo("x509_hash:abc123");
    }

    @Test
    void formatValue_leavesPlainClientIdUnprefixed() {
        assertThat(Oid4vpClientIdScheme.PLAIN.formatValue("wallet-mock")).isEqualTo("wallet-mock");
    }

    @Test
    void computeClientId_plain_keepsOriginalClientId() {
        assertThat(Oid4vpClientIdScheme.PLAIN.computeClientId("wallet-mock", null))
                .isEqualTo("wallet-mock");
    }

    @Test
    void computeClientId_x509SanDns_usesDnsSubjectAlternativeName() throws Exception {
        String pemCertificate = toPem(generateCertificate("test.example.org"));

        assertThat(Oid4vpClientIdScheme.X509_SAN_DNS.computeClientId("ignored", pemCertificate))
                .isEqualTo("x509_san_dns:test.example.org");
    }

    @Test
    void computeClientId_x509Hash_usesCertificateSha256Digest() throws Exception {
        X509Certificate certificate = generateCertificate("hash.example.org");
        String pemCertificate = toPem(certificate);
        String expectedHash = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));

        assertThat(Oid4vpClientIdScheme.X509_HASH.computeClientId("ignored", pemCertificate))
                .isEqualTo("x509_hash:" + expectedHash);
    }

    @Test
    void computeClientId_certificateBoundWithoutCertificate_keepsOriginalClientId() {
        assertThat(Oid4vpClientIdScheme.X509_HASH.computeClientId("wallet-mock", null))
                .isEqualTo("wallet-mock");
    }

    @Test
    void validateCertificateBinding_acceptsSelfSignedCertificateBecauseTheWalletDecides() throws Exception {
        String pemCertificate = toPem(generateCertificate("self-signed.example.org"));

        // A wallet following the high assurance profile rejects this, which the verifier warns
        // about, but the decision is the wallet's and not every deployment faces such a wallet.
        assertThatCode(() -> Oid4vpClientIdScheme.X509_HASH.validateCertificateBinding(pemCertificate))
                .doesNotThrowAnyException();
    }

    @Test
    void validateCertificateBinding_acceptsCaIssuedChain() throws Exception {
        KeyPair issuerKeyPair = generateEcKey().toKeyPair();
        X509Certificate caCertificate = generateCaCertificate("issuer.example.org", issuerKeyPair);
        X509Certificate leafCertificate = generateCertificate("leaf.example.org", issuerKeyPair, caCertificate);
        String pemChain = toPem(leafCertificate) + toPem(caCertificate);

        assertThatCode(() -> Oid4vpClientIdScheme.X509_HASH.validateCertificateBinding(pemChain))
                .doesNotThrowAnyException();
    }

    @Test
    void validateCertificateBinding_acceptsSingleNonSelfSignedLeafCertificate() throws Exception {
        KeyPair issuerKeyPair = generateEcKey().toKeyPair();
        X509Certificate caCertificate = generateCaCertificate("issuer.example.org", issuerKeyPair);
        X509Certificate leafCertificate = generateCertificate("leaf.example.org", issuerKeyPair, caCertificate);

        assertThatCode(() -> Oid4vpClientIdScheme.X509_HASH.validateCertificateBinding(toPem(leafCertificate)))
                .doesNotThrowAnyException();
    }

    @Test
    void validateCertificateBinding_rejectsAChainWhoseLinksDoNotSignEachOther() throws Exception {
        KeyPair issuerKeyPair = generateEcKey().toKeyPair();
        X509Certificate caCertificate = generateCaCertificate("issuer.example.org", issuerKeyPair);
        X509Certificate foreignLeaf = generateCertificate("foreign.example.org");
        String pemChain = toPem(foreignLeaf) + toPem(caCertificate);

        // The verifier puts this chain into the request object, so an incoherent one is its own bug
        assertThatThrownBy(() -> Oid4vpClientIdScheme.X509_HASH.validateCertificateBinding(pemChain))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void validateCertificateBinding_certificateBoundSchemeNeedsACertificate() {
        assertThatThrownBy(() -> Oid4vpClientIdScheme.X509_HASH.validateCertificateBinding("  "))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requires an X.509 certificate");

        assertThatCode(() -> Oid4vpClientIdScheme.PLAIN.validateCertificateBinding(null))
                .doesNotThrowAnyException();
    }

    private static X509Certificate generateCertificate(String dnsName) throws Exception {
        ECKey ecKey = generateEcKey();
        return generateLeafCertificate(dnsName, ecKey.toKeyPair(), null, null);
    }

    private static X509Certificate generateCertificate(
            String dnsName, KeyPair issuerKeyPair, X509Certificate issuerCertificate) throws Exception {
        ECKey ecKey = generateEcKey();
        return generateLeafCertificate(dnsName, ecKey.toKeyPair(), issuerKeyPair, issuerCertificate);
    }

    private static X509Certificate generateLeafCertificate(
            String dnsName, KeyPair subjectKeyPair, KeyPair issuerKeyPair, X509Certificate issuerCertificate)
            throws Exception {
        ECPublicKey publicKey = (ECPublicKey) subjectKeyPair.getPublic();
        X500Principal subject = new X500Principal("CN=" + dnsName);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000);
        X500Principal issuer = issuerCertificate != null ? issuerCertificate.getSubjectX500Principal() : subject;

        JcaX509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(issuer, BigInteger.ONE, notBefore, notAfter, subject, publicKey);
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateBuilder.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certificateBuilder.addExtension(
                Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKey));
        if (issuerCertificate != null) {
            certificateBuilder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extensionUtils.createAuthorityKeyIdentifier(issuerCertificate));
        }
        KeyPair effectiveIssuerKeyPair = issuerKeyPair != null ? issuerKeyPair : subjectKeyPair;
        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withECDSA").build(effectiveIssuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
    }

    private static X509Certificate generateCaCertificate(String dnsName, KeyPair keyPair) throws Exception {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        X500Principal subject = new X500Principal("CN=" + dnsName);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000);

        JcaX509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, notBefore, notAfter, subject, publicKey);
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certificateBuilder.addExtension(
                Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKey));
        certificateBuilder.addExtension(
                Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(publicKey));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
    }

    private static ECKey generateEcKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).generate();
    }

    private static String toPem(X509Certificate certificate) throws Exception {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
    }
}
