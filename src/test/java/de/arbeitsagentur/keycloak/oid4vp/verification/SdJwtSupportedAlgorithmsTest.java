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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.JWS_ALG_ES256;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.JWS_ALG_ES384;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.JWS_ALG_ES512;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.JWS_ALG_RS256;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;

class SdJwtSupportedAlgorithmsTest {

    private static final String AUDIENCE = "https://verifier.example";
    private static final String NONCE = "test-nonce";

    private SdJwtVerifier verifier;
    private JwtKeyMaterial issuerMaterial;
    private X509Certificate issuerCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtSupportedAlgorithmsTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        verifier = new SdJwtVerifier(60, 300);
        issuerMaterial = JwtAlgorithmSpec.ES256.generateKeyMaterial();
        issuerCert = generateSelfSignedCert(issuerMaterial, "CN=Issuer");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("supportedJwtAlgorithms")
    void verify_supportedIssuerAlgorithms_pass(JwtAlgorithmSpec algorithm) throws Exception {
        JwtKeyMaterial material = algorithm.generateKeyMaterial();
        X509Certificate cert = generateSelfSignedCert(material, "CN=" + algorithm.name());
        String sdJwt = buildIssuerSdJwt(material, cert, Map.of("iss", "https://issuer.example", "vct", "PID"));

        SdJwtVerificationResult result = verifier.verify(sdJwt, null, null, List.of(cert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.credentialType()).isEqualTo("PID");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("supportedJwtAlgorithms")
    void verify_supportedKeyBindingAlgorithms_pass(JwtAlgorithmSpec algorithm) throws Exception {
        JwtKeyMaterial holderMaterial = algorithm.generateKeyMaterial();
        String credentialJwt = buildIssuerSignedJwt(
                issuerMaterial,
                issuerCert,
                Map.of(
                        "iss", "https://issuer.example",
                        "vct", "PID",
                        "cnf", Map.of("jwk", holderMaterial.publicJwk().toJSONObject())));
        String sdJwt = buildSdJwtVpWithKbJwt(credentialJwt, holderMaterial, algorithm.jwsAlgorithm(), AUDIENCE, NONCE);

        SdJwtVerificationResult result = verifier.verify(sdJwt, AUDIENCE, NONCE, List.of(issuerCert));

        assertThat(result.issuer()).isEqualTo("https://issuer.example");
        assertThat(result.credentialType()).isEqualTo("PID");
    }

    static Stream<JwtAlgorithmSpec> supportedJwtAlgorithms() {
        return Stream.of(
                JwtAlgorithmSpec.ES256, JwtAlgorithmSpec.ES384, JwtAlgorithmSpec.ES512, JwtAlgorithmSpec.RS256);
    }

    private String buildIssuerSdJwt(JwtKeyMaterial material, X509Certificate cert, Map<String, Object> claims)
            throws Exception {
        return buildIssuerSignedJwt(material, cert, claims) + "~";
    }

    private String buildIssuerSignedJwt(JwtKeyMaterial material, X509Certificate cert, Map<String, Object> claims)
            throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issueTime(Date.from(Instant.now()))
                .notBeforeTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)));
        for (var entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(material.algorithm())
                        .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
                        .build(),
                builder.build());
        signedJwt.sign(material.signer());
        return signedJwt.serialize();
    }

    private String buildSdJwtVpWithKbJwt(
            String credentialJwt, JwtKeyMaterial holderMaterial, JWSAlgorithm algorithm, String audience, String nonce)
            throws Exception {
        String unboundPresentation = credentialJwt + "~";
        byte[] hash =
                MessageDigest.getInstance("SHA-256").digest(unboundPresentation.getBytes(StandardCharsets.US_ASCII));
        String sdHash = Base64URL.encode(hash).toString();

        SignedJWT kbJwt = new SignedJWT(
                new JWSHeader.Builder(algorithm)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(audience)
                        .claim("nonce", nonce)
                        .claim("sd_hash", sdHash)
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                        .build());
        kbJwt.sign(holderMaterial.signer());
        return unboundPresentation + kbJwt.serialize();
    }

    private static X509Certificate generateSelfSignedCert(JwtKeyMaterial material, String dn) throws Exception {
        Instant now = Instant.now();
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                new X500Principal(dn),
                                BigInteger.valueOf(System.nanoTime()),
                                Date.from(now.minus(1, ChronoUnit.HOURS)),
                                Date.from(now.plus(365, ChronoUnit.DAYS)),
                                new X500Principal(dn),
                                material.publicKey())
                        .build(new JcaContentSignerBuilder(material.certificateSignatureAlgorithm())
                                .build(material.privateKey())));
    }

    record JwtKeyMaterial(
            JWSAlgorithm algorithm,
            JWK publicJwk,
            PublicKey publicKey,
            PrivateKey privateKey,
            JWSSigner signer,
            String certificateSignatureAlgorithm) {}

    record JwtAlgorithmSpec(String name, JWSAlgorithm jwsAlgorithm) {

        static final JwtAlgorithmSpec ES256 = new JwtAlgorithmSpec(JWS_ALG_ES256, JWSAlgorithm.ES256);
        static final JwtAlgorithmSpec ES384 = new JwtAlgorithmSpec(JWS_ALG_ES384, JWSAlgorithm.ES384);
        static final JwtAlgorithmSpec ES512 = new JwtAlgorithmSpec(JWS_ALG_ES512, JWSAlgorithm.ES512);
        static final JwtAlgorithmSpec RS256 = new JwtAlgorithmSpec(JWS_ALG_RS256, JWSAlgorithm.RS256);

        JwtKeyMaterial generateKeyMaterial() throws Exception {
            return switch (name) {
                case JWS_ALG_ES256 -> ec(Curve.P_256, jwsAlgorithm, "SHA256withECDSA");
                case JWS_ALG_ES384 -> ec(Curve.P_384, jwsAlgorithm, "SHA384withECDSA");
                case JWS_ALG_ES512 -> ec(Curve.P_521, jwsAlgorithm, "SHA512withECDSA");
                case JWS_ALG_RS256 -> rsa(2048, jwsAlgorithm, "SHA256withRSA");
                default -> throw new IllegalStateException("Unsupported algorithm " + name);
            };
        }

        private static JwtKeyMaterial ec(Curve curve, JWSAlgorithm algorithm, String certificateSignatureAlgorithm)
                throws JOSEException {
            ECKey key = new ECKeyGenerator(curve).generate();
            return new JwtKeyMaterial(
                    algorithm,
                    key.toPublicJWK(),
                    key.toECPublicKey(),
                    key.toECPrivateKey(),
                    new ECDSASigner(key),
                    certificateSignatureAlgorithm);
        }

        private static JwtKeyMaterial rsa(int bits, JWSAlgorithm algorithm, String certificateSignatureAlgorithm)
                throws JOSEException {
            RSAKey key = new RSAKeyGenerator(bits).generate();
            return new JwtKeyMaterial(
                    algorithm,
                    key.toPublicJWK(),
                    key.toRSAPublicKey(),
                    key.toRSAPrivateKey(),
                    new RSASSASigner(key),
                    certificateSignatureAlgorithm);
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
