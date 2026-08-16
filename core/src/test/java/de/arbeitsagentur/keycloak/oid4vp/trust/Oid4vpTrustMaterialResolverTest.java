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

import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthorityType;
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
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

class Oid4vpTrustMaterialResolverTest {

    private static final String PID = "urn:eudi:pid:1";
    private static final String BADGE = "https://kc.example/badge";

    @Test
    void aggregatesTrustAcrossAliasesAndSkipsUnknownOnes() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=CA", "CN=CA", true);
        ResolvedTrust x509Trust = trustOf(ca, "aki-1", "https://tl.example/list.jwt");
        JWK jwk = new ECPublicJWK();
        jwk.setKeyId("jwk-1");

        Map<String, Oid4vpTrustMaterialIdentityProvider<?>> providers = Map.of(
                "x509-trust",
                FixedTrustMaterialIdentityProvider.serving(x509Trust),
                "jwk-trust",
                new UpstreamStyleTrustDouble(List.of(jwk)));
        Oid4vpTrustMaterialResolver resolver =
                new Oid4vpTrustMaterialResolver((session, alias) -> providers.get(alias));

        CredentialTrustPlan plan = resolver.resolvePlan(null, "x509-trust, jwk-trust, unknown");
        ResolvedTrust trust = plan.forCredentialType(PID);

        assertThat(trust.issuanceTrust()).isEqualTo(x509Trust.issuanceTrust());
        assertThat(trust.pinnedCertificates()).containsExactly(ca);
        assertThat(trust.revocationCertificates()).containsExactly(ca);
        assertThat(trust.trustedIssuerKeys()).containsExactly(TrustedIssuerKey.ofAnyIssuer(jwk));
        assertThat(trust.trustedAuthorities())
                .containsExactly(
                        new TrustedAuthority(TrustedAuthorityType.ETSI_TL, List.of("https://tl.example/list.jwt")),
                        new TrustedAuthority(TrustedAuthorityType.AKI, List.of("aki-1")));
        assertThat(trust.hasIssuerTrust()).isTrue();
        assertThat(plan.isScopedByCredentialType())
                .as("providers without declared credential types serve everything")
                .isFalse();
    }

    @Test
    void aProviderOfTheUpstreamContractIsScopedByItsConfiguration() {
        // Keycloak's default-trust publishes the JWKs of an issuer that has no trust list. It knows
        // nothing of this extension, so its scope has to come from its configuration.
        JWK issuerKey = new ECPublicJWK();
        issuerKey.setKeyId("issuer-jwk");
        IdentityProviderModel model = new IdentityProviderModel();
        model.getConfig().put(ServedCredentialTypes.CONFIG_KEY, BADGE);

        CredentialTrustPlan plan =
                new CredentialTrustPlan(List.of(new Oid4vpTrustMaterialResolver.UpstreamTrustMaterialAdapter(
                        new UpstreamOnlyTrustDouble(model, List.of(issuerKey)))));

        assertThat(plan.isScopedByCredentialType()).isTrue();
        assertThat(plan.forCredentialType(BADGE).trustedIssuerKeys())
                .containsExactly(TrustedIssuerKey.ofAnyIssuer(issuerKey));
        assertThat(plan.forCredentialType(PID).trustedIssuerKeys())
                .as("keys published for one credential type do not verify another")
                .isEmpty();
    }

    @Test
    void aProviderOfTheUpstreamContractWithoutAScopeStillServesEverything() {
        JWK issuerKey = new ECPublicJWK();
        issuerKey.setKeyId("issuer-jwk");

        CredentialTrustPlan plan =
                new CredentialTrustPlan(List.of(new Oid4vpTrustMaterialResolver.UpstreamTrustMaterialAdapter(
                        new UpstreamOnlyTrustDouble(new IdentityProviderModel(), List.of(issuerKey)))));

        assertThat(plan.isScopedByCredentialType()).isFalse();
        assertThat(plan.forCredentialType(PID).trustedIssuerKeys())
                .containsExactly(TrustedIssuerKey.ofAnyIssuer(issuerKey));
    }

    @Test
    void credentialTypesSeeOnlyTheTrustOfTheProvidersServingThem() throws Exception {
        KeyPair pidCaKp = generateKeyPair();
        X509Certificate pidCa = generateCert(pidCaKp, pidCaKp, "CN=PID CA", "CN=PID CA", true);
        KeyPair badgeCaKp = generateKeyPair();
        X509Certificate badgeCa = generateCert(badgeCaKp, badgeCaKp, "CN=Badge CA", "CN=Badge CA", true);

        Map<String, Oid4vpTrustMaterialIdentityProvider<?>> providers = Map.of(
                "pid-tl",
                        FixedTrustMaterialIdentityProvider.serving(
                                trustOf(pidCa, "pid-aki", "https://tl.example/eudi.jwt"), PID),
                "badge-ca", FixedTrustMaterialIdentityProvider.serving(trustOf(badgeCa, "badge-aki", null), BADGE));
        CredentialTrustPlan plan = new Oid4vpTrustMaterialResolver((session, alias) -> providers.get(alias))
                .resolvePlan(null, "pid-tl,badge-ca");

        assertThat(plan.isScopedByCredentialType()).isTrue();
        assertThat(plan.forCredentialType(PID).pinnedCertificates()).containsExactly(pidCa);
        assertThat(plan.forCredentialType(BADGE).pinnedCertificates()).containsExactly(badgeCa);
        assertThat(plan.forCredentialType(PID).trustedAuthorities())
                .containsExactly(
                        new TrustedAuthority(TrustedAuthorityType.ETSI_TL, List.of("https://tl.example/eudi.jwt")),
                        new TrustedAuthority(TrustedAuthorityType.AKI, List.of("pid-aki")));
        assertThat(plan.forCredentialType(BADGE).trustedAuthorities())
                .containsExactly(new TrustedAuthority(TrustedAuthorityType.AKI, List.of("badge-aki")));
    }

    @Test
    void credentialTypeNoProviderServesHasNoTrustAtAll() throws Exception {
        KeyPair caKp = generateKeyPair();
        X509Certificate ca = generateCert(caKp, caKp, "CN=PID CA", "CN=PID CA", true);
        Map<String, Oid4vpTrustMaterialIdentityProvider<?>> providers =
                Map.of("pid-tl", FixedTrustMaterialIdentityProvider.serving(trustOf(ca, "pid-aki", null), PID));
        CredentialTrustPlan plan =
                new Oid4vpTrustMaterialResolver((session, alias) -> providers.get(alias)).resolvePlan(null, "pid-tl");

        assertThat(plan.serves(BADGE)).isFalse();
        assertThat(plan.forCredentialType(BADGE).hasIssuerTrust()).isFalse();
        assertThat(plan.forCredentialType(BADGE).hasDeclaredTrustSource())
                .as("a configured trust plan covers every type, so an unserved one fails closed instead of"
                        + " falling back to the issuer's self-published metadata")
                .isTrue();
    }

    @Test
    void unscopedProvidersAlsoServeCredentialTypesOfScopedOnes() throws Exception {
        KeyPair pidCaKp = generateKeyPair();
        X509Certificate pidCa = generateCert(pidCaKp, pidCaKp, "CN=PID CA", "CN=PID CA", true);
        KeyPair anyCaKp = generateKeyPair();
        X509Certificate anyCa = generateCert(anyCaKp, anyCaKp, "CN=Any CA", "CN=Any CA", true);

        Map<String, Oid4vpTrustMaterialIdentityProvider<?>> providers = Map.of(
                "pid-tl", FixedTrustMaterialIdentityProvider.serving(trustOf(pidCa, "pid-aki", null), PID),
                "any-ca", FixedTrustMaterialIdentityProvider.serving(trustOf(anyCa, "any-aki", null)));
        CredentialTrustPlan plan = new Oid4vpTrustMaterialResolver((session, alias) -> providers.get(alias))
                .resolvePlan(null, "pid-tl,any-ca");

        assertThat(plan.forCredentialType(PID).pinnedCertificates()).containsExactlyInAnyOrder(pidCa, anyCa);
        assertThat(plan.forCredentialType(BADGE).pinnedCertificates()).containsExactly(anyCa);
    }

    @Test
    void emptyAliasesResolveToEmptyTrust() {
        Oid4vpTrustMaterialResolver resolver = new Oid4vpTrustMaterialResolver((session, alias) -> null);

        assertThat(resolver.resolvePlan(null, null).hasProviders()).isFalse();
        assertThat(resolver.resolvePlan(null, "  ").forCredentialType(PID)).isEqualTo(ResolvedTrust.empty());
        assertThat(ResolvedTrust.empty().hasIssuerTrust()).isFalse();
    }

    private static ResolvedTrust trustOf(
            X509Certificate certificate, String authorityKeyIdentifier, String trustListUrl) {
        List<TrustedAuthority> trustedAuthorities = Stream.concat(
                        trustListUrl == null
                                ? Stream.<TrustedAuthority>empty()
                                : TrustedAuthority.of(TrustedAuthorityType.ETSI_TL, List.of(trustListUrl)).stream(),
                        TrustedAuthority.of(TrustedAuthorityType.AKI, List.of(authorityKeyIdentifier)).stream())
                .toList();
        return new ResolvedTrust(
                List.of(new X509TrustMaterial(Set.of(certificate), List.of())),
                TestTrust.anyIssuer(List.of(certificate)),
                List.of(),
                List.of(certificate),
                trustedAuthorities,
                true);
    }

    /** Double for a provider that implements the upstream contract only, such as default-trust. */
    private record UpstreamOnlyTrustDouble(IdentityProviderModel config, List<JWK> keys)
            implements TrustMaterialIdentityProvider<IdentityProviderModel> {

        @Override
        public IdentityProviderModel getConfig() {
            return config;
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            return keys.stream();
        }

        @Override
        public void close() {}
    }

    private record UpstreamStyleTrustDouble(List<JWK> keys)
            implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        @Override
        public IdentityProviderModel getConfig() {
            return new IdentityProviderModel();
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            return keys.stream();
        }

        @Override
        public void close() {}
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKeyPair, KeyPair issuerKeyPair, String subject, String issuer, boolean ca) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Principal(subject),
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
