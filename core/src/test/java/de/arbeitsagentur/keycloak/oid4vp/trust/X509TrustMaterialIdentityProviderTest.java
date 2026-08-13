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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

/** Covers the default chain validation methods mirrored from Keycloak main. */
class X509TrustMaterialIdentityProviderTest {

    private static final TrustMaterialRequest EMPTY_REQUEST =
            TrustMaterialRequest.builder().build();

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(X509TrustMaterialIdentityProviderTest.class.getClassLoader());
    }

    @Test
    void providerWithoutX509TrustSkipsChainValidation() throws Exception {
        TrustMaterialDouble provider = new TrustMaterialDouble(List.of());

        assertThat(provider.validateX509Chain(EMPTY_REQUEST, List.of("ignored"), "ES256"))
                .isNull();
    }

    @Test
    void x509TrustMandatesPresentedChain() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=CA", "CN=CA", true);
        TrustMaterialDouble provider = new TrustMaterialDouble(List.of(new X509TrustMaterial(Set.of(ca), List.of())));

        assertThatThrownBy(() -> provider.validateX509Chain(EMPTY_REQUEST, List.of(), "ES256"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("no x5c");
        assertThatThrownBy(() -> provider.validateX509Chain(EMPTY_REQUEST, null, "ES256"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("no x5c");
    }

    @Test
    void validChainReturnsLeafKeyOfFirstMatchingMaterial() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=CA", "CN=CA", true);
        KeyPair otherCaKp = generateKeyPair();
        X509Certificate otherCa = generateCert(otherCaKp, otherCaKp, "CN=Other CA", "CN=Other CA", true);
        KeyPair leafKp = generateKeyPair();
        X509Certificate leaf = generateCert(leafKp, caKp, "CN=Leaf", "CN=CA", false);

        TrustMaterialDouble provider = new TrustMaterialDouble(List.of(
                new X509TrustMaterial(Set.of(otherCa), List.of()), new X509TrustMaterial(Set.of(ca), List.of())));

        JWK leafKey = provider.validateX509Chain(EMPTY_REQUEST, List.of(encode(leaf)), "ES256");

        assertThat(leafKey).isNotNull();
        assertThat(leafKey.getAlgorithm()).isEqualTo("ES256");
    }

    @Test
    void unverifiableChainSurfacesLastFailure() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=CA", "CN=CA", true);
        KeyPair strangerKp = generateKeyPair();
        KeyPair leafKp = generateKeyPair();
        X509Certificate strangerLeaf = generateCert(leafKp, strangerKp, "CN=Stranger Leaf", "CN=Stranger CA", false);

        TrustMaterialDouble provider = new TrustMaterialDouble(List.of(new X509TrustMaterial(Set.of(ca), List.of())));

        assertThatThrownBy(() -> provider.validateX509Chain(EMPTY_REQUEST, List.of(encode(strangerLeaf)), "ES256"))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void staticValidationWithoutMaterialsReturnsNull() throws Exception {
        assertThat(X509TrustMaterialIdentityProvider.validateX509Chain(List.of(), List.of("ignored"), "ES256"))
                .isNull();
    }

    /** Minimal provider double exposing fixed X.509 trust material. */
    private static class TrustMaterialDouble implements X509TrustMaterialIdentityProvider<IdentityProviderModel> {

        private final List<X509TrustMaterial> materials;

        TrustMaterialDouble(List<X509TrustMaterial> materials) {
            this.materials = materials;
        }

        @Override
        public IdentityProviderModel getConfig() {
            return new IdentityProviderModel();
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            return Stream.empty();
        }

        @Override
        public Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
            return materials.stream();
        }

        @Override
        public void close() {}
    }

    private static String encode(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp, KeyPair issuerKp, String subjectDn, String issuerDn, boolean isCa) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli() + System.nanoTime() % 1000),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
