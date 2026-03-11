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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;

class Oid4vpSigningKeyParserTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpSigningKeyParserTest.class.getClassLoader());
    }

    @Test
    void signingJwkRoundTrip_preservesX5cChain() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair caKeyPair = generator.generateKeyPair();
        KeyPair leafKeyPair = generator.generateKeyPair();

        X509Certificate caCertificate = createCertificate("CN=Test CA", caKeyPair, null, caKeyPair, true, null);
        X509Certificate leafCertificate =
                createCertificate("CN=Leaf", leafKeyPair, "CN=Test CA", caKeyPair, false, "test.example.org");

        String jwkJson = Oid4vpSigningKeyParser.serialize(
                leafKeyPair.getPublic(), leafKeyPair.getPrivate(), List.of(leafCertificate, caCertificate));

        KeyWrapper keyWrapper = Oid4vpSigningKeyParser.parse(jwkJson);

        assertThat(keyWrapper.getCertificateChain()).hasSize(2);
        assertThat(keyWrapper.getCertificate()).isEqualTo(leafCertificate);
    }

    private static X509Certificate createCertificate(
            String subjectDn,
            KeyPair subjectKeyPair,
            String issuerDn,
            KeyPair issuerKeyPair,
            boolean ca,
            String dnsSubjectAlternativeName)
            throws Exception {
        X500Principal subject = new X500Principal(subjectDn);
        X500Principal issuer = new X500Principal(issuerDn == null ? subjectDn : issuerDn);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                notBefore,
                notAfter,
                subject,
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (dnsSubjectAlternativeName != null) {
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dnsSubjectAlternativeName)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
