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

import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthorityType;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

class CredentialTrustPlanTest {

    private static final String PID = "urn:eudi:pid:1";

    /**
     * Building the authorization request must not depend on the trust material being reachable. A
     * trust list that cannot be fetched has to fail the presentation, not the login page.
     */
    @Test
    void trustedAuthoritiesAreAdvertisedWithoutPullingTrustMaterial() {
        CredentialTrustPlan plan = new CredentialTrustPlan(List.of(new UnreachableTrustMaterialProvider()));

        assertThat(plan.trustedAuthoritiesFor(PID))
                .containsExactly(new TrustedAuthority(TrustedAuthorityType.ETSI_TL, List.of("https://tl.example")));

        assertThatThrownBy(() -> plan.forCredentialType(PID))
                .as("the same provider fails when the material itself is needed")
                .isInstanceOf(IdentityBrokerException.class);
    }

    @Test
    void resolvedTrustIsMemoisedPerCredentialType() {
        CountingTrustMaterialProvider provider = new CountingTrustMaterialProvider();
        CredentialTrustPlan plan = new CredentialTrustPlan(List.of(provider));

        plan.forCredentialType(PID);
        plan.forCredentialType(PID);
        plan.forCredentialType(null);

        assertThat(provider.resolutions)
                .as("one resolution per credential type, plus one for the unscoped trust")
                .isEqualTo(2);
    }

    @Test
    void servingType_isTheDeclaredTypeNearestToTheCredential() {
        FixedTrustMaterialIdentityProvider pidProvider =
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(), PID);
        FixedTrustMaterialIdentityProvider germanPidProvider =
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(), "urn:eudi:pid:de:1");

        CredentialTrustPlan baseOnly = new CredentialTrustPlan(List.of(pidProvider));
        assertThat(baseOnly.servingType("urn:eudi:pid:de:1", List.of()))
                .as("a base type's provider serves the derived types without a provider of their own")
                .isEqualTo(PID);
        assertThat(baseOnly.servingType("urn:example:national-pid:1", List.of(PID)))
                .as("aka_vcts leads to the base type's provider")
                .isEqualTo(PID);
        assertThat(baseOnly.serves("urn:eudi:pid:de:1")).isTrue();

        FixedTrustMaterialIdentityProvider nationalPidProvider =
                FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(), "urn:example:national-pid:1");
        CredentialTrustPlan ownTypeDeclared = new CredentialTrustPlan(List.of(pidProvider, nationalPidProvider));
        assertThat(ownTypeDeclared.servingType("urn:example:national-pid:1", List.of(PID)))
                .as("the credential's own type takes precedence over what aka_vcts names")
                .isEqualTo("urn:example:national-pid:1");
        assertThat(ownTypeDeclared.servingType("urn:example:national-pid:de:1", List.of(PID)))
                .as("a base type of the credential's own type comes before aka_vcts as well")
                .isEqualTo("urn:example:national-pid:1");

        CredentialTrustPlan both = new CredentialTrustPlan(List.of(pidProvider, germanPidProvider));
        assertThat(both.servingType("urn:eudi:pid:de:1", List.of()))
                .as("a provider declared for the derived type takes precedence")
                .isEqualTo("urn:eudi:pid:de:1");
        assertThat(both.servingType(PID, List.of()))
                .as("the base type never inherits downwards")
                .isEqualTo(PID);
    }

    @Test
    void servingType_isTheTypeItselfWhenNoProviderDeclaresAnyOfItsTypes() {
        CredentialTrustPlan plan = new CredentialTrustPlan(
                List.of(FixedTrustMaterialIdentityProvider.serving(TestTrust.ofCertificates(), "urn:eudi:mdl:1")));

        assertThat(plan.servingType("urn:eudi:pid:de:1", List.of())).isEqualTo("urn:eudi:pid:de:1");
        assertThat(plan.serves("urn:eudi:pid:de:1")).isFalse();
    }

    /** Advertises its trust domain but cannot serve the material behind it. */
    private static class UnreachableTrustMaterialProvider
            implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        @Override
        public IdentityProviderModel getConfig() {
            return new IdentityProviderModel();
        }

        @Override
        public List<TrustedAuthority> trustedAuthorities() {
            return TrustedAuthority.of(TrustedAuthorityType.ETSI_TL, List.of("https://tl.example"));
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            throw new IdentityBrokerException("Trust list unreachable");
        }

        @Override
        public Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
            throw new IdentityBrokerException("Trust list unreachable");
        }

        @Override
        public List<X509Certificate> directIssuerCertificates() {
            throw new IdentityBrokerException("Trust list unreachable");
        }

        @Override
        public void close() {}
    }

    private static class CountingTrustMaterialProvider
            implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        private int resolutions;

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
            resolutions++;
            return Stream.empty();
        }

        @Override
        public void close() {}
    }
}
