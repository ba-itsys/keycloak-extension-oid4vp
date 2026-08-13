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
package de.arbeitsagentur.keycloak.oid4vp.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/** Mirrors the ClaimPath test cases of upstream Keycloak's OID4VP mapper work. */
class ClaimPathTest {

    @Test
    void parsesFieldSteps() {
        List<ClaimPath.Step> steps = ClaimPath.parse("address.locality").steps();

        assertThat(steps).containsExactly(fieldStep("address"), fieldStep("locality"));
    }

    @Test
    void parsesSelectorSteps() {
        assertThat(ClaimPath.parse("degrees[].type").steps())
                .containsExactly(fieldStep("degrees"), allElementsStep(), fieldStep("type"));
        assertThat(ClaimPath.parse("degrees[0].type").steps())
                .containsExactly(fieldStep("degrees"), firstElementStep(), fieldStep("type"));
        assertThat(ClaimPath.parse("matrix[][]").steps())
                .containsExactly(fieldStep("matrix"), allElementsStep(), allElementsStep());
    }

    @Test
    void parsesEscapedDotAsLiteralFieldName() {
        assertThat(ClaimPath.parse("org\\.example").steps()).containsExactly(fieldStep("org.example"));
    }

    @Test
    void rejectsMalformedPaths() {
        for (String malformed : new String[] {
            null,
            "",
            "[0]",
            "degrees[x]",
            "degrees[1]",
            "degrees[2]",
            "degrees[10]",
            "degrees[-1]",
            "degrees[00]",
            "degrees[*]",
            "degrees[",
            "degrees[]x",
            "degrees[]]",
            "degrees[[]]",
            "address.",
            "degrees[].",
            "org\\.",
            "org\\\\."
        }) {
            assertThat(ClaimPath.parse(malformed)).as("path '%s'", malformed).isNull();
        }
    }

    @Test
    void gibberishNeverThrowsAndSelectsNothing() throws Exception {
        List<String> gibberish = List.of(
                ".",
                "..",
                "a..b",
                "*",
                "***",
                "\\",
                "a\\",
                "§$%&!?",
                "🔥💥",
                "[[[]]]",
                "]][[",
                "a[b]c[d]",
                "[*]",
                "*[*]*",
                "a]b[c",
                " ");
        for (String path : gibberish) {
            ClaimPath parsed = ClaimPath.parse(path);
            if (parsed != null) {
                assertThat(parsed.select(claims()))
                        .as("gibberish '%s' must select nothing", path)
                        .isEmpty();
            }
        }
    }

    @Test
    void stepsAreImmutable() {
        List<ClaimPath.Step> steps = ClaimPath.parse("email").steps();

        assertThatThrownBy(() -> steps.add(fieldStep("more"))).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void selectsScalarAndNestedClaims() throws Exception {
        assertThat(selectSingle("email").textValue()).isEqualTo("alice@email.cz");
        assertThat(selectSingle("address.locality").textValue()).isEqualTo("London");
    }

    @Test
    void selectsWholeArrayAsOneMatch() throws Exception {
        JsonNode match = selectSingle("nationalities");

        assertThat(match.isArray()).isTrue();
        assertThat(match).hasSize(2);
    }

    @Test
    void allElementsSelectorFansOutAndSkipsNullValues() throws Exception {
        List<JsonNode> matches = ClaimPath.parse("degrees[].type").select(claims());

        assertThat(matches).extracting(JsonNode::textValue).containsExactly("BSc", "MSc");
    }

    @Test
    void firstElementSelectorTakesTheFirstPresentedElement() throws Exception {
        assertThat(selectSingle("nationalities[0]").textValue()).isEqualTo("DE");
        assertThat(selectSingle("degrees[0].type").textValue()).isEqualTo("BSc");
        assertThat(ClaimPath.parse("none[0]").select(claims())).isEmpty();
    }

    @Test
    void deadEndsSelectNothing() throws Exception {
        assertThat(ClaimPath.parse("missing").select(claims())).isEmpty();
        assertThat(ClaimPath.parse("empty").select(claims())).isEmpty();
        assertThat(ClaimPath.parse("email.nested").select(claims())).isEmpty();
        assertThat(ClaimPath.parse("email[]").select(claims())).isEmpty();
        assertThat(ClaimPath.parse("address[]").select(claims())).isEmpty();
        assertThat(ClaimPath.parse("email").select(null)).isEmpty();
    }

    private static JsonNode selectSingle(String path) throws Exception {
        List<JsonNode> matches = ClaimPath.parse(path).select(claims());
        assertThat(matches).as("expected exactly one match for %s", path).hasSize(1);
        return matches.get(0);
    }

    private static ClaimPath.Step fieldStep(String name) {
        return new ClaimPath.Step(name, ClaimPath.Step.Kind.FIELD);
    }

    private static ClaimPath.Step allElementsStep() {
        return new ClaimPath.Step(null, ClaimPath.Step.Kind.ALL_ELEMENTS);
    }

    private static ClaimPath.Step firstElementStep() {
        return new ClaimPath.Step(null, ClaimPath.Step.Kind.FIRST_ELEMENT);
    }

    private static JsonNode claims() throws Exception {
        return JsonSerialization.readValue("""
                {
                  "email": "alice@email.cz",
                  "empty": null,
                  "address": {"locality": "London"},
                  "nationalities": ["DE", "CZ"],
                  "degrees": [{"type": "BSc"}, {"type": "MSc"}, {"type": null}],
                  "none": [],
                  "org.example": "literal"
                }""", JsonNode.class);
    }
}
