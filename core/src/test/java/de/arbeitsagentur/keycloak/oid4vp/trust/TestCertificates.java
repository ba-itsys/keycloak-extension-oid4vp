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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class TestCertificates {

    private TestCertificates() {}

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    // A generated Keycloak realm key carries a self-signed end entity certificate.
    public static X509Certificate selfSigned(String subject) throws Exception {
        KeyPair keyPair = generateKeyPair();
        return issue(keyPair, keyPair, subject, subject, false);
    }

    public static X509Certificate issue(
            KeyPair subjectKeyPair, KeyPair issuerKeyPair, String subject, String issuer, boolean certificateAuthority)
            throws Exception {
        return issue(subjectKeyPair, issuerKeyPair, subject, issuer, certificateAuthority, List.of());
    }

    public static X509Certificate issue(
            KeyPair subjectKeyPair,
            KeyPair issuerKeyPair,
            String subject,
            String issuer,
            boolean certificateAuthority,
            List<String> crlDistributionPoints)
            throws Exception {
        Instant now = Instant.now();
        GeneralName[] names = crlDistributionPoints.stream()
                .map(url -> new GeneralName(GeneralName.uniformResourceIdentifier, url))
                .toArray(GeneralName[]::new);
        return issue(
                subjectKeyPair,
                issuerKeyPair,
                subject,
                issuer,
                certificateAuthority,
                names,
                now.minus(1, ChronoUnit.DAYS),
                now.plus(365, ChronoUnit.DAYS));
    }

    public static X509Certificate issueExpired(
            KeyPair subjectKeyPair, KeyPair issuerKeyPair, String subject, String issuer, boolean certificateAuthority)
            throws Exception {
        Instant now = Instant.now();
        return issue(
                subjectKeyPair,
                issuerKeyPair,
                subject,
                issuer,
                certificateAuthority,
                new GeneralName[0],
                now.minus(2, ChronoUnit.DAYS),
                now.minus(1, ChronoUnit.DAYS));
    }

    public static X509Certificate issueWithDirectoryNameDistributionPoint(
            KeyPair subjectKeyPair, KeyPair issuerKeyPair, String subject, String issuer, String directoryName)
            throws Exception {
        Instant now = Instant.now();
        return issue(
                subjectKeyPair,
                issuerKeyPair,
                subject,
                issuer,
                false,
                new GeneralName[] {new GeneralName(new X500Name(directoryName))},
                now.minus(1, ChronoUnit.DAYS),
                now.plus(365, ChronoUnit.DAYS));
    }

    private static X509Certificate issue(
            KeyPair subjectKeyPair,
            KeyPair issuerKeyPair,
            String subject,
            String issuer,
            boolean certificateAuthority,
            GeneralName[] distributionPoints,
            Instant notBefore,
            Instant notAfter)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Principal(subject),
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(certificateAuthority));
        if (distributionPoints.length > 0) {
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(new DistributionPointName(new GeneralNames(distributionPoints)), null, null)
            }));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    public static byte[] crl(KeyPair issuerKeyPair, String issuer, Instant nextUpdate, X509Certificate... revoked)
            throws Exception {
        return sign(issuerKeyPair, crlBuilder(issuer, Instant.now().minusSeconds(60), nextUpdate, revoked));
    }

    public static byte[] crlIssuedAt(
            KeyPair issuerKeyPair, String issuer, Instant thisUpdate, Instant nextUpdate, X509Certificate... revoked)
            throws Exception {
        return sign(issuerKeyPair, crlBuilder(issuer, thisUpdate, nextUpdate, revoked));
    }

    public static byte[] crlWithExtension(
            KeyPair issuerKeyPair, String issuer, Instant nextUpdate, String extensionOid, ASN1Encodable value)
            throws Exception {
        X509v2CRLBuilder builder = crlBuilder(issuer, Instant.now(), nextUpdate);
        builder.addExtension(new ASN1ObjectIdentifier(extensionOid), true, value);
        return sign(issuerKeyPair, builder);
    }

    private static X509v2CRLBuilder crlBuilder(
            String issuer, Instant thisUpdate, Instant nextUpdate, X509Certificate... revoked) {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(issuer), Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(nextUpdate));
        for (X509Certificate certificate : revoked) {
            builder.addCRLEntry(certificate.getSerialNumber(), Date.from(thisUpdate), CRLReason.keyCompromise);
        }
        return builder;
    }

    private static byte[] sign(KeyPair issuerKeyPair, X509v2CRLBuilder builder) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
        return builder.build(signer).getEncoded();
    }
}
