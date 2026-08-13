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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwk.JWK;

class X509CertificateChainValidatorTest {

    private KeyPair rootKp;
    private X509Certificate rootCert;
    private KeyPair intermediateKp;
    private X509Certificate intermediateCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(X509CertificateChainValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        rootKp = generateKeyPair();
        rootCert = generateCert(rootKp, rootKp, "CN=Root CA", "CN=Root CA", true, validNow(), null);
        intermediateKp = generateKeyPair();
        intermediateCert = generateCert(intermediateKp, rootKp, "CN=Issuing CA", "CN=Root CA", true, validNow(), null);
    }

    @Test
    void validatesLeafOnlyChainAgainstIssuingCaAnchor() throws Exception {
        X509Certificate leaf = leafCert(intermediateKp, "CN=Issuing CA");

        JWK jwk = X509CertificateChainValidator.validate(encode(leaf), "ES256", Set.of(intermediateCert), List.of());

        assertThat(jwk).isNotNull();
        assertThat(jwk.getAlgorithm()).isEqualTo("ES256");
    }

    @Test
    void validatesChainThatIncludesTheTrustedIntermediate() throws Exception {
        // The wallet presents [leaf, issuing CA] and the trust list contains the issuing CA. The
        // previous hand-rolled validator required the anchor to be the *parent* of the chain top
        // and rejected this shape.
        X509Certificate leaf = leafCert(intermediateKp, "CN=Issuing CA");

        JWK jwk = X509CertificateChainValidator.validate(
                encode(leaf, intermediateCert), "ES256", Set.of(intermediateCert), List.of());

        assertThat(jwk).isNotNull();
    }

    @Test
    void validatesFullChainAgainstRootAnchor() throws Exception {
        X509Certificate leaf = leafCert(intermediateKp, "CN=Issuing CA");

        JWK jwk = X509CertificateChainValidator.validate(
                encode(leaf, intermediateCert), "ES256", Set.of(rootCert), List.of());

        assertThat(jwk).isNotNull();
    }

    @Test
    void rejectsChainWithoutPathToAnyAnchor() throws Exception {
        KeyPair otherKp = generateKeyPair();
        X509Certificate otherCa = generateCert(otherKp, otherKp, "CN=Other CA", "CN=Other CA", true, validNow(), null);
        X509Certificate leaf = leafCert(intermediateKp, "CN=Issuing CA");

        assertThatThrownBy(() -> X509CertificateChainValidator.validate(
                        encode(leaf, intermediateCert), "ES256", Set.of(otherCa), List.of()))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void rejectsSelfSignedLeaf() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate selfSigned = generateCert(leafKp, leafKp, "CN=Self", "CN=Self", false, validNow(), null);

        assertThatThrownBy(() -> X509CertificateChainValidator.validate(
                        encode(selfSigned), "ES256", Set.of(rootCert), List.of()))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("Self signed");
    }

    @Test
    void rejectsCaCertificateAsLeaf() throws Exception {
        assertThatThrownBy(() -> X509CertificateChainValidator.validate(
                        encode(intermediateCert), "ES256", Set.of(rootCert), List.of()))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("end entity");
    }

    @Test
    void rejectsExpiredLeaf() throws Exception {
        KeyPair leafKp = generateKeyPair();
        X509Certificate expired = generateCert(
                leafKp,
                intermediateKp,
                "CN=Expired",
                "CN=Issuing CA",
                false,
                new Validity(
                        Instant.now().minus(10, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.DAYS)),
                null);

        assertThatThrownBy(() -> X509CertificateChainValidator.validate(
                        encode(expired, intermediateCert), "ES256", Set.of(rootCert), List.of()))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void rejectsGarbageAndOversizedChains() {
        assertThatThrownBy(() -> X509CertificateChainValidator.decodeCertificateChain(List.of()))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("empty");
        assertThatThrownBy(() -> X509CertificateChainValidator.decodeCertificateChain(null))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("empty");
        assertThatThrownBy(() -> X509CertificateChainValidator.decodeCertificateChain(List.of("bm90LWEtY2VydA==")))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("Failed to decode");
        List<String> tooLong = Collections.nCopies(11, "AAAA");
        assertThatThrownBy(() -> X509CertificateChainValidator.decodeCertificateChain(tooLong))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("too long");
    }

    @Test
    void convertsRsaLeafKeyToJwk() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair rsaLeafKp = generator.generateKeyPair();
        X509Certificate rsaLeaf = generateRsaCert(rsaLeafKp, "CN=RSA Leaf");

        JWK jwk = X509CertificateChainValidator.toJwk(rsaLeaf, "RS256", List.of(rsaLeaf));

        assertThat(jwk.getAlgorithm()).isEqualTo("RS256");
        assertThat(jwk.getKeyType()).isEqualTo("RSA");
    }

    @Test
    void enforcesRequiredExtendedKeyUsage() throws Exception {
        String mdlDsEku = "1.0.18013.5.1.2";
        KeyPair leafKp = generateKeyPair();
        X509Certificate leafWithoutEku = leafCert(intermediateKp, "CN=Issuing CA");
        X509Certificate leafWithEku = generateCert(
                leafKp,
                intermediateKp,
                "CN=DS",
                "CN=Issuing CA",
                false,
                validNow(),
                new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(mdlDsEku))));

        assertThatThrownBy(() -> X509CertificateChainValidator.validate(
                        encode(leafWithoutEku, intermediateCert), "ES256", Set.of(rootCert), List.of(mdlDsEku)))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("extended key usages");

        JWK jwk = X509CertificateChainValidator.validate(
                encode(leafWithEku, intermediateCert), "ES256", Set.of(rootCert), List.of(mdlDsEku));
        assertThat(jwk).isNotNull();
    }

    private X509Certificate leafCert(KeyPair issuerKp, String issuerDn) throws Exception {
        KeyPair leafKp = generateKeyPair();
        return generateCert(leafKp, issuerKp, "CN=Leaf", issuerDn, false, validNow(), null);
    }

    private static List<String> encode(X509Certificate... certificates) throws Exception {
        return Arrays.stream(certificates)
                .map(certificate -> {
                    try {
                        return Base64.getEncoder().encodeToString(certificate.getEncoded());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                })
                .toList();
    }

    private static X509Certificate generateRsaCert(KeyPair keyPair, String dn) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(dn),
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(validNow().notBefore()),
                Date.from(validNow().notAfter()),
                new X500Principal(dn),
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private record Validity(Instant notBefore, Instant notAfter) {}

    private static Validity validNow() {
        return new Validity(
                Instant.now().minus(1, ChronoUnit.DAYS), Instant.now().plus(365, ChronoUnit.DAYS));
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
            boolean isCa,
            Validity validity,
            ExtendedKeyUsage extendedKeyUsage)
            throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli() + System.nanoTime() % 1000),
                Date.from(validity.notBefore()),
                Date.from(validity.notAfter()),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (extendedKeyUsage != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
