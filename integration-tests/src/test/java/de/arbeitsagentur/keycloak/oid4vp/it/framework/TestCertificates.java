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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.PemUtils;

public final class TestCertificates {

    private TestCertificates() {}

    /**
     * Generates a fresh CA + leaf certificate chain with the SAN {@code test.example.com} and
     * returns it as combined PEM (leaf, CA, private key) suitable for the identity provider's
     * x509 certificate configuration.
     */
    public static String generateHaipCertificateChainPem() {
        try {
            KeyPair caKeyPair = generateEcKeyPair();
            KeyPair leafKeyPair = generateEcKeyPair();
            X509Certificate caCert = generateCaCert(caKeyPair);
            X509Certificate leafCert = generateLeafCertWithSan(leafKeyPair, caKeyPair, "test.example.com");
            return toPem("CERTIFICATE", leafCert.getEncoded())
                    + "\n"
                    + toPem("CERTIFICATE", caCert.getEncoded())
                    + "\n"
                    + toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate HAIP certificate chain", e);
        }
    }

    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    public static X509Certificate generateCaCert(KeyPair caKeyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // Certificates signed by this CA derive their authority key identifier from this extension
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caKeyPair.getPublic()));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    public static X509Certificate generateLeafCertWithSan(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
            throws Exception {
        X500Principal issuer = new X500Principal("CN=Test CA");
        X500Principal subject = new X500Principal("CN=" + dnsName);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(2),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic());
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    public static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }

    public static X509Certificate parseCertificate(String pem) {
        try {
            return PemUtils.decodeCertificate(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate PEM", e);
        }
    }

    /**
     * The certificate's subject key identifier, base64url encoded without padding. Credentials
     * issued under this certificate carry the same value in their authority key identifier, which
     * is what DCQL {@code trusted_authorities} entries of type {@code aki} advertise.
     */
    public static String subjectKeyIdentifierBase64Url(X509Certificate certificate) {
        try {
            SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.fromExtensions(
                    new X509CertificateHolder(certificate.getEncoded()).getExtensions());
            if (subjectKeyIdentifier == null) {
                throw new IllegalStateException("Certificate has no subject key identifier extension");
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(subjectKeyIdentifier.getKeyIdentifier());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read the subject key identifier", e);
        }
    }
}
