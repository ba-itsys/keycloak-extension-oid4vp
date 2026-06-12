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
package de.arbeitsagentur.keycloak.oid4vp.conformance.verifier;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

/**
 * Verifier signing material for the conformance run: a CA and a leaf certificate with the
 * Keycloak public host as SAN, the combined PEM for the identity provider configuration, the
 * leaf JWK uploaded to the suite, and the x509_hash client id.
 */
public final class VerifierSigningMaterial {

    private static VerifierSigningMaterial instance;

    private final String combinedPem;
    private final String leafCertPem;
    private final String caCertPem;
    private final String jwkJson;
    private final String x509Hash;

    private VerifierSigningMaterial(
            String combinedPem, String leafCertPem, String caCertPem, String jwkJson, String x509Hash) {
        this.combinedPem = combinedPem;
        this.leafCertPem = leafCertPem;
        this.caCertPem = caCertPem;
        this.jwkJson = jwkJson;
        this.x509Hash = x509Hash;
    }

    public static synchronized VerifierSigningMaterial forHost(String host) {
        if (instance == null) {
            instance = generate(host);
        }
        return instance;
    }

    public String combinedPem() {
        return combinedPem;
    }

    public String leafCertPem() {
        return leafCertPem;
    }

    public String caCertPem() {
        return caCertPem;
    }

    public String jwkJson() {
        return jwkJson;
    }

    public String x509Hash() {
        return x509Hash;
    }

    private static VerifierSigningMaterial generate(String host) {
        try {
            KeyPair caKeyPair = generateEcKeyPair();
            KeyPair leafKeyPair = generateEcKeyPair();
            X509Certificate caCert = generateCaCert(caKeyPair);
            X509Certificate leafCert = generateLeafCert(leafKeyPair, caKeyPair, host);

            String leafCertPem = toPem("CERTIFICATE", leafCert.getEncoded());
            String caCertPem = toPem("CERTIFICATE", caCert.getEncoded());
            String combinedPem = leafCertPem + "\n" + caCertPem + "\n"
                    + toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded()) + "\n";

            String jwkJson = new ECKey.Builder(Curve.P_256, (ECPublicKey) leafKeyPair.getPublic())
                    .privateKey((ECPrivateKey) leafKeyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWSAlgorithm.ES256)
                    .x509CertChain(List.of(Base64.encode(leafCert.getEncoded())))
                    .build()
                    .toJSONString();
            String x509Hash = Base64Url.encode(HashUtils.hash(JavaAlgorithm.SHA256, leafCert.getEncoded()));

            return new VerifierSigningMaterial(combinedPem, leafCertPem, caCertPem, jwkJson, x509Hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate verifier signing material", e);
        }
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate generateCaCert(KeyPair caKeyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=OIDF Verifier Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(2, ChronoUnit.DAYS)),
                subject,
                caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateLeafCert(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
            throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=OIDF Verifier Test CA"),
                BigInteger.valueOf(2),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(2, ChronoUnit.DAYS)),
                new X500Principal("CN=" + dnsName),
                leafKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {
            KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth
        }));
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static String toPem(String type, byte[] der) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }
}
