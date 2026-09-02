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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class X509TrustMaterialTest {

    @Test
    void acceptsSelfSignedRootCaAnchor() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X509Certificate root = generateCert(rootKp, rootKp, "CN=Root CA", "CN=Root CA", true, null);

        X509TrustMaterial material = new X509TrustMaterial(Set.of(root), List.of());

        assertThat(material.trustAnchors()).containsExactly(root);
    }

    @Test
    void acceptsIntermediateCaAnchor() throws Exception {
        // ETSI trust lists commonly list the issuing (intermediate) CA of a trust domain, not the
        // root. Such anchors are CA certificates that are neither self-issued nor self-signed.
        KeyPair rootKp = generateKeyPair();
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate intermediate = generateCert(intermediateKp, rootKp, "CN=Issuing CA", "CN=Root CA", true, null);

        X509TrustMaterial material = new X509TrustMaterial(Set.of(intermediate), List.of());

        assertThat(material.trustAnchors()).containsExactly(intermediate);
    }

    @Test
    void rejectsEndEntityCertificateAsAnchor() throws Exception {
        KeyPair rootKp = generateKeyPair();
        KeyPair leafKp = generateKeyPair();
        X509Certificate leaf = generateCert(leafKp, rootKp, "CN=Leaf", "CN=Root CA", false, null);

        assertThatThrownBy(() -> new X509TrustMaterial(Set.of(leaf), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CA certificates");
    }

    @Test
    void rejectsCaAnchorWithoutCertificateSigningKeyUsage() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X509Certificate root =
                generateCert(rootKp, rootKp, "CN=Root CA", "CN=Root CA", true, new KeyUsage(KeyUsage.digitalSignature));

        assertThatThrownBy(() -> new X509TrustMaterial(Set.of(root), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("certificate signing");
    }

    @Test
    void rejectsEmptyAnchors() {
        assertThatThrownBy(() -> new X509TrustMaterial(Set.of(), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("At least one");
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp, KeyPair issuerKp, String subjectDn, String issuerDn, boolean isCa, KeyUsage keyUsage)
            throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, keyUsage);
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
