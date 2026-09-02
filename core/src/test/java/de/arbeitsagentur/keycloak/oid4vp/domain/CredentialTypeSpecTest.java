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
import org.junit.jupiter.api.Test;

class CredentialTypeSpecTest {

    private static final String PID = "urn:eudi:pid:1";
    private static final String PID_NAMESPACE = "eu.europa.ec.eudi.pid.1";

    @Test
    void requestedClaims_expandAlternativePathsBehindTheirClaimInSpecOrder() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("given_name"),
                ClaimSpec.sdJwt("birth_family_name", List.of("1-full")).withAlternativePaths(List.of("birth_name")),
                ClaimSpec.sdJwt("birthdate"));

        assertThat(spec.requestedClaims())
                .extracting(ClaimSpec::path)
                .containsExactly("given_name", "birth_family_name", "birth_name", "birthdate");
        assertThat(spec.requestedClaims().get(2).claimSetIds())
                .as("an alternative is a member of the same claim sets as its claim")
                .containsExactly("1-full");
        assertThat(spec.requestedClaims())
                .allSatisfy(claim -> assertThat(claim.alternativePaths()).isEmpty());
    }

    @Test
    void requestedClaims_withoutAlternatives_areTheClaimSpecs() {
        CredentialTypeSpec spec = sdJwt(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("family_name"));

        assertThat(spec.requestedClaims()).isEqualTo(spec.claimSpecs());
    }

    @Test
    void claimSetOptionIndexes_withoutIdsOrAlternatives_isEmpty() {
        CredentialTypeSpec spec = sdJwt(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("family_name"));

        assertThat(spec.claimSetOptionIndexes())
                .as("no claim_sets means every claim is required")
                .isEmpty();
    }

    @Test
    void claimSetOptionIndexes_claimSetIdsOnly_oneOptionPerIdWithUntaggedClaimsInEveryOption() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("given_name", List.of("1-full")),
                ClaimSpec.sdJwt("family_name", List.of("2-min", "1-full")),
                ClaimSpec.sdJwt("birthdate"));

        assertThat(spec.claimSetOptionIndexes()).containsExactly(List.of(0, 1, 2), List.of(1, 2));
    }

    @Test
    void claimSetOptionIndexes_alternativesWithoutIds_oneOptionPerPathOfTheClaim() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("given_name"),
                ClaimSpec.sdJwt("birth_family_name").withAlternativePaths(List.of("birth_name")));

        assertThat(spec.claimSetOptionIndexes())
                .as("the claim itself is preferred, the alternative is the fallback")
                .containsExactly(List.of(0, 1), List.of(0, 2));
    }

    @Test
    void claimSetOptionIndexes_severalAlternatives_areTriedInTheirOrder() {
        CredentialTypeSpec spec =
                sdJwt(ClaimSpec.sdJwt("birth_family_name").withAlternativePaths(List.of("birth_name", "maiden_name")));

        assertThat(spec.claimSetOptionIndexes()).containsExactly(List.of(0), List.of(1), List.of(2));
    }

    @Test
    void claimSetOptionIndexes_alternativesMultiplyEveryClaimSetIdOption() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("given_name", List.of("1-full")),
                ClaimSpec.sdJwt("birth_family_name", List.of("1-full", "2-min"))
                        .withAlternativePaths(List.of("birth_name")),
                ClaimSpec.sdJwt("birthdate"));

        assertThat(spec.claimSetOptionIndexes())
                .as("1-full under both paths of the birth name, then 2-min under both")
                .containsExactly(List.of(0, 1, 3), List.of(0, 2, 3), List.of(1, 3), List.of(2, 3));
    }

    @Test
    void claimSetOptionIndexes_alternativeOfAClaimOutsideAnOption_doesNotMultiplyThatOption() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("given_name", List.of("1-full")).withAlternativePaths(List.of("given_names")),
                ClaimSpec.sdJwt("family_name", List.of("1-full", "2-min")));

        assertThat(spec.claimSetOptionIndexes()).containsExactly(List.of(0, 2), List.of(1, 2), List.of(2));
    }

    @Test
    void claimSetOptionIndexes_severalClaimsWithAlternatives_formTheCrossProductPreferringTheClaimsThemselves() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("birth_family_name").withAlternativePaths(List.of("birth_name")),
                ClaimSpec.sdJwt("place_of_birth").withAlternativePaths(List.of("birth_place")),
                ClaimSpec.sdJwt("birthdate"));

        assertThat(spec.claimSetOptionIndexes())
                .as(
                        "the first option asks for every claim under its own path; the last claim's alternative varies fastest")
                .containsExactly(List.of(0, 2, 4), List.of(0, 3, 4), List.of(1, 2, 4), List.of(1, 3, 4));
    }

    @Test
    void claimSetOptionIndexes_alternativesAndSeveralIds_growWithTheProductOfBoth() {
        CredentialTypeSpec spec = sdJwt(
                ClaimSpec.sdJwt("a", List.of("1", "2")).withAlternativePaths(List.of("a2")),
                ClaimSpec.sdJwt("b", List.of("1", "2")).withAlternativePaths(List.of("b2")),
                ClaimSpec.sdJwt("c", List.of("1")));

        List<List<Integer>> options = spec.claimSetOptionIndexes();

        assertThat(options)
                .as("two ids, each multiplied by two claims with two paths")
                .hasSize(8);
        assertThat(options.subList(0, 4))
                .containsExactly(List.of(0, 2, 4), List.of(0, 3, 4), List.of(1, 2, 4), List.of(1, 3, 4));
        assertThat(options.subList(4, 8)).containsExactly(List.of(0, 2), List.of(0, 3), List.of(1, 2), List.of(1, 3));
    }

    @Test
    void requestedClaims_mdocAlternatives_keepTheNamespace() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_MSO_MDOC,
                PID_NAMESPACE,
                List.of(
                        ClaimSpec.mdoc(PID_NAMESPACE, "given_name"),
                        ClaimSpec.mdoc(PID_NAMESPACE, "birth_family_name")
                                .withAlternativePaths(List.of("birth_name"))));

        assertThat(spec.requestedClaims())
                .containsExactly(
                        ClaimSpec.mdoc(PID_NAMESPACE, "given_name"),
                        ClaimSpec.mdoc(PID_NAMESPACE, "birth_family_name"),
                        ClaimSpec.mdoc(PID_NAMESPACE, "birth_name"));
        assertThat(spec.claimSetOptionIndexes()).containsExactly(List.of(0, 1), List.of(0, 2));
    }

    @Test
    void types_holdEveryAcceptedTypeWithTheFirstDerivingTheId() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_SD_JWT_VC, List.of(PID, "urn:eudi:pid:de:1"), List.of(ClaimSpec.sdJwt("sub")));

        assertThat(spec.types()).containsExactly(PID, "urn:eudi:pid:de:1");
        assertThat(spec.firstType()).isEqualTo(PID);
        assertThat(new CredentialTypeSpec(Oid4vpConstants.FORMAT_SD_JWT_VC, PID, List.of()).types())
                .containsExactly(PID);
    }

    @Test
    void types_mustNotBeEmpty() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new CredentialTypeSpec(Oid4vpConstants.FORMAT_SD_JWT_VC, List.of(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseTypes_trimsAndDeduplicatesTheCommaSeparatedList() {
        assertThat(CredentialTypeSpec.parseTypes(" urn:eudi:pid:1 , urn:eudi:pid:de:1,, urn:eudi:pid:1 "))
                .containsExactly("urn:eudi:pid:1", "urn:eudi:pid:de:1");
        assertThat(CredentialTypeSpec.parseTypes(null)).isEmpty();
        assertThat(CredentialTypeSpec.parseTypes(" ")).isEmpty();
    }

    private static CredentialTypeSpec sdJwt(ClaimSpec... claimSpecs) {
        return new CredentialTypeSpec(Oid4vpConstants.FORMAT_SD_JWT_VC, PID, List.of(claimSpecs));
    }
}
