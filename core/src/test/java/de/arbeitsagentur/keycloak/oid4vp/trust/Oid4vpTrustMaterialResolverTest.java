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
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

class Oid4vpTrustMaterialResolverTest {

    @Test
    void aggregatesTrustAcrossAliasesAndSkipsUnknownOnes() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=CA", "CN=CA", true);
        X509TrustMaterial material = new X509TrustMaterial(Set.of(ca), List.of());
        JWK jwk = new ECPublicJWK();
        jwk.setKeyId("jwk-1");

        Map<String, Oid4vpTrustMaterialIdentityProvider<?>> providers = Map.of(
                "x509-trust", new X509TrustDouble(material, List.of(ca), "https://tl.example/list.jwt"),
                "jwk-trust", new JwkOnlyTrustDouble(List.of(jwk)));
        Oid4vpTrustMaterialResolver resolver =
                new Oid4vpTrustMaterialResolver((session, alias) -> providers.get(alias));

        ResolvedTrust trust = resolver.resolveTrust(null, "x509-trust, jwk-trust, unknown");

        assertThat(trust.issuanceTrust()).containsExactly(material);
        assertThat(trust.directIssuerCertificates()).containsExactly(ca);
        assertThat(trust.trustedIssuerJwks()).containsExactly(jwk);
        assertThat(trust.revocationCertificates()).containsExactly(ca);
        assertThat(trust.authorityKeyIdentifiers()).containsExactly("aki-1");
        assertThat(trust.trustListUrls()).containsExactly("https://tl.example/list.jwt");
        assertThat(trust.hasIssuerTrust()).isTrue();
    }

    @Test
    void emptyAliasesResolveToEmptyTrust() {
        Oid4vpTrustMaterialResolver resolver = new Oid4vpTrustMaterialResolver((session, alias) -> null);

        assertThat(resolver.resolveTrust(null, null)).isEqualTo(ResolvedTrust.empty());
        assertThat(resolver.resolveTrust(null, "  ")).isEqualTo(ResolvedTrust.empty());
        assertThat(ResolvedTrust.empty().hasIssuerTrust()).isFalse();
    }

    /** Trust material double serving the full extension surface. */
    private static class X509TrustDouble implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        private final X509TrustMaterial material;
        private final List<X509Certificate> certificates;
        private final String trustListUrl;

        X509TrustDouble(X509TrustMaterial material, List<X509Certificate> certificates, String trustListUrl) {
            this.material = material;
            this.certificates = certificates;
            this.trustListUrl = trustListUrl;
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
            return Stream.of(material);
        }

        @Override
        public List<X509Certificate> directIssuerCertificates() {
            return certificates;
        }

        @Override
        public List<X509Certificate> revocationCertificates() {
            return certificates;
        }

        @Override
        public List<String> trustedAuthorityKeyIdentifiers() {
            return List.of("aki-1");
        }

        @Override
        public Optional<String> trustListUrl() {
            return Optional.of(trustListUrl);
        }

        @Override
        public void close() {}
    }

    /**
     * Double for an upstream-style provider that only exposes JWKs; the extension surfaces stay at
     * their empty defaults, matching what the resolver's adapter produces for Keycloak's
     * default-trust.
     */
    private static class JwkOnlyTrustDouble implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        private final List<JWK> jwks;

        JwkOnlyTrustDouble(List<JWK> jwks) {
            this.jwks = jwks;
        }

        @Override
        public IdentityProviderModel getConfig() {
            return new IdentityProviderModel();
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            return jwks.stream();
        }

        @Override
        public void close() {}
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
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
