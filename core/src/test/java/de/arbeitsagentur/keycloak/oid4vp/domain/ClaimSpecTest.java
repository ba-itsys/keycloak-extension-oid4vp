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

class ClaimSpecTest {

    @Test
    void expand_requestsTheClaimFirstAndEveryAlternativeUnderTheClaimIdAndSluggedPath() {
        ClaimSpec spec = ClaimSpec.sdJwt("birth_family_name", List.of("1-full"))
                .withId("birth-name")
                .withAlternativePaths(List.of("birth_name", "names.birth[0]"));

        List<ClaimSpec> expanded = spec.expand();

        assertThat(expanded)
                .extracting(ClaimSpec::id)
                .containsExactly("birth-name", "birth-name-birth_name", "birth-name-names_birth_0_");
        assertThat(expanded)
                .extracting(ClaimSpec::path)
                .containsExactly("birth_family_name", "birth_name", "names.birth[0]");
        assertThat(expanded).allSatisfy(claim -> {
            assertThat(claim.claimSetIds()).containsExactly("1-full");
            assertThat(claim.alternativePaths()).isEmpty();
        });
    }

    @Test
    void expand_withoutAlternatives_isTheClaimItself() {
        ClaimSpec spec = ClaimSpec.sdJwt("given_name").withId("given-name");

        assertThat(spec.expand()).containsExactly(spec);
    }

    @Test
    void expand_withoutId_leavesTheAlternativesUnnamed() {
        ClaimSpec spec = ClaimSpec.sdJwt("birth_family_name").withAlternativePaths(List.of("birth_name"));

        assertThat(spec.expand()).extracting(ClaimSpec::id).containsExactly(null, null);
    }

    @Test
    void expand_mdocAlternatives_shareTheNamespace() {
        ClaimSpec spec = ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "birth_family_name")
                .withAlternativePaths(List.of("birth_name"));

        assertThat(spec.expand())
                .extracting(ClaimSpec::namespace)
                .containsExactly("eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.pid.1");
    }

    @Test
    void pathsWellFormed_requiresTheClaimAndEveryAlternativeToParse() {
        assertThat(ClaimSpec.sdJwt("birth_family_name")
                        .withAlternativePaths(List.of("birth_name", "names[]"))
                        .pathsWellFormed())
                .isTrue();
        assertThat(ClaimSpec.sdJwt("birth_family_name")
                        .withAlternativePaths(List.of("birth_name[x]"))
                        .pathsWellFormed())
                .as("a malformed alternative misconfigures the claim as a whole")
                .isFalse();
        assertThat(ClaimSpec.sdJwt("names[x]")
                        .withAlternativePaths(List.of("birth_name"))
                        .pathsWellFormed())
                .isFalse();
    }

    @Test
    void parseAlternativePaths_trimsAndDeduplicatesTheCommaSeparatedList() {
        assertThat(ClaimSpec.parseAlternativePaths(" birth_name , , birth_name,address.locality "))
                .containsExactly("birth_name", "address.locality");
        assertThat(ClaimSpec.parseAlternativePaths(null)).isEmpty();
        assertThat(ClaimSpec.parseAlternativePaths("  ")).isEmpty();
    }
}
