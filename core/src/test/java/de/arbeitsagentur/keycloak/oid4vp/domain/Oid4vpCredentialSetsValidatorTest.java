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

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The credential set configuration rules. An empty credential map stands for an identity provider
 * without mappers, where only the rules that need no mapper knowledge apply.
 */
class Oid4vpCredentialSetsValidatorTest {

    private static final String PID = "sdjwt_urn_eudi_pid_1";
    private static final String MDL = "mdoc_org_iso_18013_5_1_mDL";

    private final ObjectMapper objectMapper = new ObjectMapper();

    // --- parsing and shape -------------------------------------------------

    @Test
    void parse_preferredThenFallback_readsOptionsInOrder() {
        List<CredentialSet> sets = CredentialSet.parse(objectMapper, """
                [{"purpose":"Login","options":[["%s","%s"],["%s"]]}]
                """.formatted(PID, MDL, PID));

        assertThat(sets).hasSize(1);
        assertThat(sets.get(0).options()).containsExactly(List.of(PID, MDL), List.of(PID));
        assertThat(sets.get(0).purpose()).isEqualTo("Login");
        assertThat(sets.get(0).required())
                .as("required defaults to true per DCQL")
                .isTrue();
    }

    @Test
    void parse_requiredFalse_isRead() {
        List<CredentialSet> sets = CredentialSet.parse(objectMapper, """
                [{"options":[["%s"]],"required":false}]
                """.formatted(MDL));

        assertThat(sets.get(0).required()).isFalse();
    }

    @Test
    void parse_malformedJson_isRejected() {
        assertThatThrownBy(() -> CredentialSet.parse(objectMapper, "[{\"options\":"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("credentialSets");
    }

    @Test
    void parse_explicitNullsReadAsAbsentMembers() {
        List<CredentialSet> sets = CredentialSet.parse(objectMapper, """
                [{"options":[["%s"]],"required":null,"purpose":null}]
                """.formatted(PID));

        assertThat(sets.get(0).required())
                .as("a serialized credential set carries null for members that were never configured")
                .isTrue();
        assertThat(sets.get(0).purpose()).isNull();
    }

    @Test
    void parse_notAnArray_isRejected() {
        assertThatThrownBy(() -> CredentialSet.parse(objectMapper, "{\"options\":[[\"" + PID + "\"]]}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("array");
    }

    @Test
    void parse_missingOptions_isRejected() {
        assertThatThrownBy(() -> CredentialSet.parse(objectMapper, "[{\"purpose\":\"Login\"}]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("options");
    }

    @Test
    void parse_emptyOptions_isRejected() {
        assertThatThrownBy(() -> CredentialSet.parse(objectMapper, "[{\"options\":[]}]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("options");
    }

    @Test
    void parse_optionIsNotAnArrayOfIds_isRejected() {
        assertThatThrownBy(() -> CredentialSet.parse(objectMapper, "[{\"options\":[\"" + PID + "\"]}]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("options");
    }

    @Test
    void validate_credentialIdWithIllegalCharacters_isReported() {
        assertThat(problems("[{\"options\":[[\"urn:eudi:pid:1\"]]}]", null))
                .singleElement()
                .asString()
                .contains("urn:eudi:pid:1");
    }

    @Test
    void validate_blankCredentialSets_isValid() {
        assertThat(problems("  ", null)).isEmpty();
    }

    // --- principal coverage across credential set options ------------------

    @Test
    void validate_principalCredentialMissingFromAnOption_isReported() {
        String json = """
                [{"options":[["%s","%s"],["%s"]]}]
                """.formatted(PID, MDL, PID);

        assertThat(problems(json, MDL))
                .singleElement()
                .asString()
                .as("the second option would be satisfiable without ever presenting the subject credential")
                .contains(MDL);
    }

    @Test
    void validate_principalCredentialInEveryRequiredOption_isValid() {
        String json = """
                [{"options":[["%s","%s"],["%s"]]}]
                """.formatted(PID, MDL, PID);

        assertThat(problems(json, PID)).isEmpty();
    }

    @Test
    void validate_optionalSetWithoutPrincipal_isValid() {
        String json = """
                [{"options":[["%s"]]},{"options":[["%s"]],"required":false}]
                """.formatted(PID, MDL);

        assertThat(problems(json, PID))
                .as("an optional extra credential is never the sole source of the subject")
                .isEmpty();
    }

    @Test
    void validate_allSetsOptional_isReported() {
        String json = """
                [{"options":[["%s"]],"required":false},{"options":[["%s"]],"required":false}]
                """.formatted(PID, MDL);

        assertThat(problems(json, PID)).singleElement().asString().contains("required");
    }

    @Test
    void validate_principalCredentialNotReferencedAtAll_isReported() {
        String json = "[{\"options\":[[\"" + PID + "\"]]}]";

        assertThat(problems(json, MDL)).singleElement().asString().contains(MDL);
    }

    // --- rules that need the aggregated credentials ------------------------

    @Test
    void validate_danglingCredentialId_isReported() {
        String json = """
                [{"options":[["%s","%s"],["%s"]]}]
                """.formatted(PID, MDL, PID);

        assertThat(problems(json, PID, "sub", Map.of(PID, pidSpec())))
                .singleElement()
                .asString()
                .contains(MDL);
    }

    @Test
    void validate_unknownPrincipalCredentialId_isReported() {
        assertThat(problems("", "nope", "sub", Map.of(PID, pidSpec())))
                .singleElement()
                .asString()
                .contains("nope");
    }

    @Test
    void validate_principalClaimRestrictedToOneClaimSetOption_isReported() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_SD_JWT_VC,
                "urn:eudi:pid:1",
                List.of(ClaimSpec.sdJwt("given_name", List.of("1-full")), ClaimSpec.sdJwt("sub", List.of("2-min"))));

        assertThat(problems("", PID, "sub", Map.of(PID, spec)))
                .singleElement()
                .asString()
                .as("a wallet answering the 1-full claim set option would present no subject")
                .contains("sub");
    }

    @Test
    void validate_principalClaimInEveryClaimSetOption_isValid() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_SD_JWT_VC,
                "urn:eudi:pid:1",
                List.of(ClaimSpec.sdJwt("given_name", List.of("1-full")), ClaimSpec.sdJwt("sub")));

        assertThat(problems("", PID, "sub", Map.of(PID, spec))).isEmpty();
    }

    @Test
    void validate_blankPrincipalCredentialId_requiresPrincipalClaimOnEveryCredential() {
        CredentialTypeSpec withoutPrincipal = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_MSO_MDOC,
                "org.iso.18013.5.1.mDL",
                List.of(ClaimSpec.mdoc("org.iso.18013.5.1", "family_name")));
        Map<String, CredentialTypeSpec> credentials = new LinkedHashMap<>();
        credentials.put(PID, pidSpec());
        credentials.put(MDL, withoutPrincipal);

        assertThat(problems("", "", "sub", credentials))
                .singleElement()
                .asString()
                .contains(MDL);
    }

    @Test
    void validate_blankPrincipalCredentialIdWithFormatAlternatives_isValid() {
        CredentialTypeSpec mdocPid = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_MSO_MDOC,
                "eu.europa.ec.eudi.pid.1",
                List.of(ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "sub")));
        Map<String, CredentialTypeSpec> credentials = new LinkedHashMap<>();
        credentials.put(PID, pidSpec());
        credentials.put("mdoc_eu_europa_ec_eudi_pid_1", mdocPid);
        String json = """
                [{"options":[["%s"],["mdoc_eu_europa_ec_eudi_pid_1"]]}]
                """.formatted(PID);

        assertThat(problems(json, "", "sub", credentials))
                .as("either format may supply the subject, so no explicit principal credential is needed")
                .isEmpty();
    }

    @Test
    void validate_principalClaimNotRequested_skipsPrincipalRules() {
        CredentialTypeSpec withoutPrincipal = new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_MSO_MDOC,
                "org.iso.18013.5.1.mDL",
                List.of(ClaimSpec.mdoc("org.iso.18013.5.1", "family_name")));

        assertThat(Oid4vpCredentialSetsValidator.problems(List.of(), Map.of(MDL, withoutPrincipal), "", "sub", false))
                .as("useIdTokenSubject and transient users do not read a principal claim")
                .isEmpty();
    }

    private static CredentialTypeSpec pidSpec() {
        return new CredentialTypeSpec(
                Oid4vpConstants.FORMAT_SD_JWT_VC,
                "urn:eudi:pid:1",
                List.of(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("sub")));
    }

    private List<String> problems(String credentialSetsJson, String principalCredentialId) {
        return problems(credentialSetsJson, principalCredentialId, "sub", Map.of());
    }

    private List<String> problems(
            String credentialSetsJson,
            String principalCredentialId,
            String principalAttribute,
            Map<String, CredentialTypeSpec> credentials) {
        List<CredentialSet> credentialSets =
                credentialSetsJson.isBlank() ? List.of() : CredentialSet.parse(objectMapper, credentialSetsJson);
        return Oid4vpCredentialSetsValidator.problems(
                credentialSets, credentials, principalCredentialId, principalAttribute, true);
    }
}
