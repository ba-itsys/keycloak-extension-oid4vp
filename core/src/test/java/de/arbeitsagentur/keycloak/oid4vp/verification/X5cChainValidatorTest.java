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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class X5cChainValidatorTest {

    private KeyPair caKeyPair;
    private X509Certificate caCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(X5cChainValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        caKeyPair = generateKeyPair();
        caCert = generateCert(
                caKeyPair,
                caKeyPair,
                "CN=Test CA",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS),
                true);
    }

    @Test
    void validateChain_validChain_returnsLeafKey() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                caKeyPair,
                "CN=Leaf",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        PublicKey result = X5cChainValidator.validateChain(encode(leafCert, caCert), List.of(caCert));
        assertThat(result).isEqualTo(leafCert.getPublicKey());
    }

    @Test
    void validateChain_expiredLeafCert_throws() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate expiredLeaf = generateCert(
                leafKp,
                caKeyPair,
                "CN=Expired Leaf",
                "CN=Test CA",
                Instant.now().minus(2, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.HOURS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateChain(encode(expiredLeaf, caCert), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Failed to validate the x5c certificate chain");
    }

    @Test
    void validateChain_notYetValidLeafCert_throws() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate futureLeaf = generateCert(
                leafKp,
                caKeyPair,
                "CN=Future Leaf",
                "CN=Test CA",
                Instant.now().plus(1, ChronoUnit.DAYS),
                Instant.now().plus(2, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateChain(encode(futureLeaf, caCert), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Failed to validate the x5c certificate chain");
    }

    @Test
    void validateChain_expiredIntermediateCert_throws() throws Exception {
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate expiredIntermediate = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=Expired Intermediate",
                "CN=Test CA",
                Instant.now().minus(2, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.HOURS),
                true);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Expired Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(
                        () -> X5cChainValidator.validateChain(encode(leafCert, expiredIntermediate), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Failed to validate the x5c certificate chain");
    }

    @Test
    void validateChain_emptyChain_throws() {
        assertThatThrownBy(() -> X5cChainValidator.validateChain(List.of(), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("The x5c certificate chain is empty");
    }

    @Test
    void validateChain_untrustedSelfSignedLeaf_throws() throws Exception {
        KeyPair untrustedKp = generateKeyPair();
        X509Certificate untrustedCert = generateCert(
                untrustedKp,
                untrustedKp,
                "CN=Untrusted",
                "CN=Untrusted",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateChain(encode(untrustedCert), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Self signed certificates are not accepted as chain leaf");
    }

    @Test
    void validateChain_noCaAmongTrusted_throws() throws Exception {
        KeyPair untrustedKp = generateKeyPair();
        X509Certificate untrustedCert = generateCert(
                untrustedKp,
                caKeyPair,
                "CN=Untrusted Leaf",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);
        KeyPair pinnedKp = generateKeyPair();
        X509Certificate pinnedEndEntity = generateCert(
                pinnedKp,
                caKeyPair,
                "CN=Pinned End Entity",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateChain(encode(untrustedCert), List.of(pinnedEndEntity)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not anchored");
    }

    @Test
    void validateChain_selfSignedLeaf_trustedDirectly_succeeds() throws Exception {
        PublicKey result = X5cChainValidator.validateChain(encode(caCert), List.of(caCert));
        assertThat(result).isEqualTo(caCert.getPublicKey());
    }

    @Test
    void validateChain_nonCaIntermediate_throws() throws Exception {
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate nonCaIntermediate = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=Intermediate",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        assertThatThrownBy(() -> X5cChainValidator.validateChain(encode(leafCert, nonCaIntermediate), List.of(caCert)))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Failed to validate the x5c certificate chain");
    }

    @Test
    void validateChain_trustedIntermediateCa_succeeds() throws Exception {
        KeyPair intermediateKp = generateKeyPair();
        X509Certificate intermediateCa = generateCert(
                intermediateKp,
                caKeyPair,
                "CN=Trusted Intermediate",
                "CN=Test CA",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                true);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = generateCert(
                leafKp,
                intermediateKp,
                "CN=Leaf",
                "CN=Trusted Intermediate",
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(1, ChronoUnit.DAYS),
                false);

        PublicKey result = X5cChainValidator.validateChain(encode(leafCert, intermediateCa), List.of(intermediateCa));
        assertThat(result).isEqualTo(leafCert.getPublicKey());
    }

    private static List<String> encode(X509Certificate... certificates) throws Exception {
        List<String> x5c = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            x5c.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        }
        return x5c;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp,
            KeyPair issuerKp,
            String subjectDn,
            String issuerDn,
            Instant notBefore,
            Instant notAfter,
            boolean isCa)
            throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
