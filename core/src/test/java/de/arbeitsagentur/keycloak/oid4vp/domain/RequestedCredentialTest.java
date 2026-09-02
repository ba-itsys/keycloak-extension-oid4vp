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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential.RequestedClaim;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.util.JsonSerialization;

class RequestedCredentialTest {

    @Test
    void of_buildsClaimsAndClaimSetOptionsFromSpec() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(
                        ClaimSpec.sdJwt("given_name", List.of("1-full")),
                        ClaimSpec.sdJwt("family_name"),
                        ClaimSpec.sdJwt("birthdate", List.of("1-full", "2-min"))));

        RequestedCredential requested = RequestedCredential.of("cred1", spec);

        assertThat(requested.format()).isEqualTo("dc+sd-jwt");
        assertThat(requested.types()).containsExactly("urn:eudi:pid:1");
        assertThat(requested.claims())
                .containsExactly(
                        new RequestedClaim(null, "given_name"),
                        new RequestedClaim(null, "family_name"),
                        new RequestedClaim(null, "birthdate"));
        assertThat(requested.claimSets()).containsExactly(List.of(0, 1, 2), List.of(1, 2));
    }

    @Test
    void of_expandsAlternativePathsIntoClaimsAndOneOptionPerPath() throws Exception {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(
                        ClaimSpec.sdJwt("given_name"),
                        ClaimSpec.sdJwt("birth_family_name").withAlternativePaths(List.of("birth_name"))));

        RequestedCredential requested = RequestedCredential.of("cred1", spec);

        assertThat(requested.claims())
                .containsExactly(
                        new RequestedClaim(null, "given_name"),
                        new RequestedClaim(null, "birth_family_name"),
                        new RequestedClaim(null, "birth_name"));
        assertThat(requested.claimSets()).containsExactly(List.of(0, 1), List.of(0, 2));
        assertThat(requested.missingClaims(json("""
                        {"given_name": "Erika", "birth_name": "Gabler"}""")))
                .as("a presentation carrying the alternative satisfies the fallback option")
                .isEmpty();
        assertThat(requested.missingClaims(json("""
                        {"given_name": "Erika"}""")))
                .as("neither path presented: the preferred option's missing claim is reported")
                .containsExactly("birth_family_name");
    }

    @Test
    void of_alternativePathsOfAnMdocClaim_stayInTheNamespace() throws Exception {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "mso_mdoc",
                "eu.europa.ec.eudi.pid.1",
                List.of(ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "birth_family_name")
                        .withAlternativePaths(List.of("birth_name"))));

        RequestedCredential requested = RequestedCredential.of("cred1", spec);

        assertThat(requested.claims())
                .containsExactly(
                        new RequestedClaim("eu.europa.ec.eudi.pid.1", "birth_family_name"),
                        new RequestedClaim("eu.europa.ec.eudi.pid.1", "birth_name"));
        assertThat(requested.missingClaims(json("""
                        {"eu.europa.ec.eudi.pid.1": {"birth_name": "Gabler"}}"""))).isEmpty();
    }

    @Test
    void of_withoutClaimSetIds_hasNoClaimSets() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt", "urn:eudi:pid:1", List.of(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("family_name")));

        assertThat(RequestedCredential.of("cred1", spec).claimSets()).isEmpty();
    }

    @Test
    void of_carriesEveryAcceptedType() {
        CredentialTypeSpec spec = new CredentialTypeSpec(
                "dc+sd-jwt", List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1"), List.of(ClaimSpec.sdJwt("given_name")));

        assertThat(RequestedCredential.of("pid", spec).types()).containsExactly("urn:eudi:pid:1", "urn:eudi:pid:de:1");
    }

    @Test
    void matches_acceptsACredentialOfAnyRequestedType() {
        RequestedCredential requested = new RequestedCredential(
                "pid", "dc+sd-jwt", List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1"), List.of(), List.of());

        assertThat(requested.matches(sdJwtOf("urn:eudi:pid:de:1"))).isTrue();
        assertThat(requested.matches(sdJwtOf("urn:eudi:pid:1"))).isTrue();
        assertThat(requested.matches(sdJwtOf("urn:eudi:diploma:1"))).isFalse();
        assertThat(requested.describeTypes()).isEqualTo("urn:eudi:pid:1, urn:eudi:pid:de:1");
    }

    @Test
    void matches_acceptsACredentialOfADerivedType() {
        RequestedCredential requested =
                new RequestedCredential("pid", "dc+sd-jwt", "urn:eudi:pid:1", List.of(), List.of());

        assertThat(requested.matches(sdJwtOf("urn:eudi:pid:de:1")))
                .as("the German PID derives from the EUDI PID by its identifier")
                .isTrue();
        assertThat(requested.matches(new VerifiedCredential(
                        "c1",
                        "https://issuer.example",
                        "urn:example:national-pid:1",
                        Map.of(),
                        PresentationType.SD_JWT,
                        List.of("urn:eudi:pid:1"))))
                .as("aka_vcts states the derivation")
                .isTrue();
        assertThat(new RequestedCredential("pid", "dc+sd-jwt", "urn:eudi:pid:de:1", List.of(), List.of())
                        .matches(sdJwtOf("urn:eudi:pid:1")))
                .as("a base type credential does not satisfy a request for the derived type")
                .isFalse();
    }

    private static VerifiedCredential sdJwtOf(String type) {
        return new VerifiedCredential("c1", "https://issuer.example", type, Map.of(), PresentationType.SD_JWT);
    }

    @Test
    void matches_comparesFormatAndType() {
        RequestedCredential sdJwt =
                new RequestedCredential("cred1", "dc+sd-jwt", "urn:eudi:pid:1", List.of(), List.of());
        RequestedCredential mdoc =
                new RequestedCredential("cred1", "mso_mdoc", "eu.europa.ec.eudi.pid.1", List.of(), List.of());

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
    void missingClaims_withoutClaimSets_requiresAllClaims() throws Exception {
        RequestedCredential requested = new RequestedCredential(
                "cred1",
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(claim("given_name"), claim("family_name"), claim("birthdate")),
                List.of());

        assertThat(requested.missingClaims(json("""
                        {"given_name": "Erika", "family_name": "M", "birthdate": "1980-01-01"}"""))).isEmpty();
        assertThat(requested.missingClaims(json("""
                {"given_name": "Erika"}"""))).containsExactly("family_name", "birthdate");
    }

    @Test
    void missingClaims_claimSets_acceptsAnySatisfiedOption() throws Exception {
        RequestedCredential requested = new RequestedCredential(
                "cred1",
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(claim("given_name"), claim("family_name"), claim("birthdate")),
                List.of(List.of(0, 1, 2), List.of(1, 2)));

        assertThat(requested.missingClaims(json("""
                        {"given_name": "Erika", "family_name": "M", "birthdate": "1980-01-01"}"""))).isEmpty();
        assertThat(requested.missingClaims(json("""
                {"family_name": "M", "birthdate": "1980-01-01"}""")))
                .as("fallback option satisfied")
                .isEmpty();
    }

    @Test
    void missingClaims_claimSets_reportsPreferredOptionWhenNoneSatisfied() throws Exception {
        RequestedCredential requested = new RequestedCredential(
                "cred1",
                "dc+sd-jwt",
                "urn:eudi:pid:1",
                List.of(claim("given_name"), claim("family_name"), claim("birthdate")),
                List.of(List.of(0, 1, 2), List.of(1, 2)));

        assertThat(requested.missingClaims(json("""
                {"given_name": "Erika"}"""))).containsExactly("family_name", "birthdate");
    }

    @Test
    void missingClaims_resolvesNestedAndNamespacedClaims() throws Exception {
        RequestedCredential sdJwt = new RequestedCredential(
                "cred1", "dc+sd-jwt", "urn:eudi:pid:1", List.of(claim("address.street_address")), List.of());
        RequestedCredential mdoc = new RequestedCredential(
                "cred1",
                "mso_mdoc",
                "org.iso.18013.5.1.mDL",
                List.of(new RequestedClaim("org.iso.18013.5.1", "family_name")),
                List.of());

        assertThat(sdJwt.missingClaims(json("""
                {"address": {"street_address": "Main St. 1"}}"""))).isEmpty();
        assertThat(sdJwt.missingClaims(json("""
                {"address": {"locality": "Berlin"}}"""))).containsExactly("address.street_address");
        assertThat(mdoc.missingClaims(json("""
                {"org.iso.18013.5.1": {"family_name": "Mustermann"}}"""))).isEmpty();
        assertThat(mdoc.missingClaims(json("{}"))).containsExactly("org.iso.18013.5.1:family_name");
    }

    @Test
    void checkIfSatisfiedBy_throwsWithMissingClaims() throws Exception {
        RequestedCredential requested = new RequestedCredential(
                "cred1", "dc+sd-jwt", "urn:eudi:pid:1", List.of(claim("given_name"), claim("family_name")), List.of());

        JsonNode presented = json("""
                {"given_name": "Erika"}""");
        assertThatThrownBy(() -> requested.checkIfSatisfiedBy(presented))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("requested claims")
                .hasMessageContaining("family_name");
    }

    private static RequestedClaim claim(String path) {
        return new RequestedClaim(null, path);
    }

    private static JsonNode json(String value) throws Exception {
        return JsonSerialization.readValue(value, JsonNode.class);
    }
}
