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

class CredentialTypeHierarchyTest {

    private static final String PID = "urn:eudi:pid:1";
    private static final String GERMAN_PID = "urn:eudi:pid:de:1";

    @Test
    void urnAncestors_dropTheQualifierSegmentsBeforeTheVersionNearestFirst() {
        assertThat(CredentialTypeHierarchy.urnAncestors(GERMAN_PID)).containsExactly(PID);
        assertThat(CredentialTypeHierarchy.urnAncestors("urn:eudi:pid:de:bavaria:1"))
                .containsExactly("urn:eudi:pid:de:1", PID);
    }

    @Test
    void urnAncestors_areEmptyForBaseTypesAndTypesWithoutAVersion() {
        assertThat(CredentialTypeHierarchy.urnAncestors(PID)).isEmpty();
        assertThat(CredentialTypeHierarchy.urnAncestors("urn:eudi:pid:de"))
                .as("a type whose last segment is no number has no version to keep")
                .isEmpty();
        assertThat(CredentialTypeHierarchy.urnAncestors("https://credentials.example/pid/de/1"))
                .as("only URN types state derivation in their identifier")
                .isEmpty();
        assertThat(CredentialTypeHierarchy.urnAncestors(null)).isEmpty();
    }

    @Test
    void typesOf_listTheTypeThenAlsoKnownAsThenAncestorsOfEach() {
        assertThat(CredentialTypeHierarchy.typesOf("urn:example:pid:at:2", List.of(GERMAN_PID)))
                .containsExactly("urn:example:pid:at:2", GERMAN_PID, "urn:example:pid:2", PID);
        assertThat(CredentialTypeHierarchy.typesOf(PID, null)).containsExactly(PID);
        assertThat(CredentialTypeHierarchy.typesOf(PID, List.of(PID, " ")))
                .as("duplicates and blanks are dropped")
                .containsExactly(PID);
    }

    @Test
    void isOfType_acceptsTheTypeItsAliasesAndItsAncestorsButNeverTheOtherWayRound() {
        assertThat(CredentialTypeHierarchy.isOfType(GERMAN_PID, List.of(), GERMAN_PID))
                .isTrue();
        assertThat(CredentialTypeHierarchy.isOfType(GERMAN_PID, List.of(), PID))
                .as("the German PID derives from the EUDI PID by its identifier")
                .isTrue();
        assertThat(CredentialTypeHierarchy.isOfType("urn:example:national-pid:1", List.of(PID), PID))
                .as("aka_vcts states the derivation for any identifier")
                .isTrue();
        assertThat(CredentialTypeHierarchy.isOfType(PID, List.of(), GERMAN_PID))
                .as("a base type credential is not of a derived type")
                .isFalse();
        assertThat(CredentialTypeHierarchy.isOfType(GERMAN_PID, List.of(), "urn:eudi:pid:2"))
                .as("another version is another type")
                .isFalse();
        assertThat(CredentialTypeHierarchy.isOfType(GERMAN_PID, List.of(), null))
                .isFalse();
    }
}
