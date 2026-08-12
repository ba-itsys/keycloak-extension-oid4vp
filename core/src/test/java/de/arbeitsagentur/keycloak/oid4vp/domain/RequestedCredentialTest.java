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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RequestedCredentialTest {

    @Test
    void of_buildsPathsAndClaimSetOptionsFromSpec() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(
                        new ClaimSpec("given_name", List.of("1-full")),
                        new ClaimSpec("family_name"),
                        new ClaimSpec("birthdate", List.of("1-full", "2-min"))));

        RequestedCredential requested = RequestedCredential.of(spec);

        assertThat(requested.format()).isEqualTo("dc+sd-jwt");
        assertThat(requested.type()).isEqualTo("urn:eudi:pid:1");
        assertThat(requested.claimPaths()).containsExactly("given_name", "family_name", "birthdate");
        assertThat(requested.claimSets())
                .containsExactly(
                        List.of("given_name", "family_name", "birthdate"), List.of("family_name", "birthdate"));
    }

    @Test
    void of_withoutClaimSetIds_hasNoClaimSets() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt", "urn:eudi:pid:1", List.of(new ClaimSpec("given_name"), new ClaimSpec("family_name")));

        RequestedCredential requested = RequestedCredential.of(spec);

        assertThat(requested.claimSets()).isEmpty();
    }

    @Test
    void matches_comparesFormatAndType() {
        RequestedCredential sdJwt = new RequestedCredential("dc+sd-jwt", "urn:eudi:pid:1", List.of(), List.of());
        RequestedCredential mdoc = new RequestedCredential("mso_mdoc", "eu.europa.ec.eudi.pid.1", List.of(), List.of());

        VerifiedCredential sdJwtCredential = new VerifiedCredential(
                "c1", "https://issuer.example", "urn:eudi:pid:1", Map.of(), PresentationType.SD_JWT);
        VerifiedCredential mdocCredential =
                new VerifiedCredential("c2", null, "eu.europa.ec.eudi.pid.1", Map.of(), PresentationType.MDOC);

        assertThat(sdJwt.matches(sdJwtCredential)).isTrue();
        assertThat(sdJwt.matches(mdocCredential)).isFalse();
        assertThat(mdoc.matches(mdocCredential)).isTrue();
        assertThat(mdoc.matches(sdJwtCredential)).isFalse();
    }

    @Test
    void missingClaims_withoutClaimSets_requiresAllClaims() {
        RequestedCredential requested = new RequestedCredential(
                "dc+sd-jwt", "urn:eudi:pid:1", List.of("given_name", "family_name", "birthdate"), List.of());

        assertThat(requested.missingClaims(
                        Map.of("given_name", "Erika", "family_name", "M", "birthdate", "1980-01-01")))
                .isEmpty();
        assertThat(requested.missingClaims(Map.of("given_name", "Erika"))).containsExactly("family_name", "birthdate");
    }

    @Test
    void missingClaims_claimSets_acceptsAnySatisfiedOption() {
        RequestedCredential requested = new RequestedCredential(
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of("given_name", "family_name", "birthdate"),
                List.of(List.of("given_name", "family_name", "birthdate"), List.of("family_name", "birthdate")));

        assertThat(requested.missingClaims(
                        Map.of("given_name", "Erika", "family_name", "M", "birthdate", "1980-01-01")))
                .isEmpty();
        assertThat(requested.missingClaims(Map.of("family_name", "M", "birthdate", "1980-01-01")))
                .as("fallback option satisfied")
                .isEmpty();
    }

    @Test
    void missingClaims_claimSets_reportsPreferredOptionWhenNoneSatisfied() {
        RequestedCredential requested = new RequestedCredential(
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of("given_name", "family_name", "birthdate"),
                List.of(List.of("given_name", "family_name", "birthdate"), List.of("family_name", "birthdate")));

        assertThat(requested.missingClaims(Map.of("given_name", "Erika"))).containsExactly("family_name", "birthdate");
    }

    @Test
    void missingClaims_resolvesNestedAndNamespacedPaths() {
        RequestedCredential sdJwt =
                new RequestedCredential("dc+sd-jwt", "urn:eudi:pid:1", List.of("address/street_address"), List.of());
        RequestedCredential mdoc = new RequestedCredential(
                "mso_mdoc", "eu.europa.ec.eudi.pid.1", List.of("eu.europa.ec.eudi.pid.1/family_name"), List.of());

        assertThat(sdJwt.missingClaims(Map.of("address", Map.of("street_address", "Main St. 1"))))
                .isEmpty();
        assertThat(sdJwt.missingClaims(Map.of("address", Map.of("locality", "Berlin"))))
                .containsExactly("address/street_address");
        assertThat(mdoc.missingClaims(Map.of("eu.europa.ec.eudi.pid.1/family_name", "Mustermann")))
                .isEmpty();
        assertThat(mdoc.missingClaims(Map.of())).containsExactly("eu.europa.ec.eudi.pid.1/family_name");
    }
}
