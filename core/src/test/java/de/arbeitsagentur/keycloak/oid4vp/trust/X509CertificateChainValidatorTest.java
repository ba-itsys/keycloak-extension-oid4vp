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
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.X509CertificateChainValidator;

/**
 * Pins the upstream validator behavior that {@link IssuerTrustAnchors} relies on: an issuing
 * CA that is not a self-signed root works as a PKIX trust anchor.
 */
class X509CertificateChainValidatorTest {

    private X509Certificate intermediateCert;
    private X509Certificate leaf;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(X509CertificateChainValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        KeyPair rootKp = generateKeyPair();
        KeyPair intermediateKp = generateKeyPair();
        intermediateCert = generateCert(intermediateKp, rootKp, "CN=Issuing CA", "CN=Root CA", true);
        leaf = generateCert(generateKeyPair(), intermediateKp, "CN=Leaf", "CN=Issuing CA", false);
    }

    @Test
    void validatesLeafOnlyChainAgainstIssuingCaAnchor() throws Exception {
        assertThat(X509CertificateChainValidator.validate(encode(leaf), "ES256", Set.of(intermediateCert), List.of()))
                .isNotNull();
    }

    @Test
    void validatesChainThatIncludesTheTrustedIntermediate() throws Exception {
        // The wallet presents [leaf, issuing CA] and the trust list contains the issuing CA, so the
        // anchor is the top of the presented chain itself.
        assertThat(X509CertificateChainValidator.validate(
                        encode(leaf, intermediateCert), "ES256", Set.of(intermediateCert), List.of()))
                .isNotNull();
    }

    private static List<String> encode(X509Certificate... certificates) {
        return Stream.of(certificates).map(PemUtils::encodeCertificate).toList();
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp, KeyPair issuerKp, String subjectDn, String issuerDn, boolean isCa) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate())));
    }
}
