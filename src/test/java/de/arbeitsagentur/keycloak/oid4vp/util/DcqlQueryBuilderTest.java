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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DcqlQueryBuilderTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private DcqlQueryBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new DcqlQueryBuilder(objectMapper);
    }

    @Test
    void build_empty_throws() {
        assertThatThrownBy(() -> builder.build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No credential types configured");
    }

    @Test
    void build_singleSdJwtCredential_correctStructure() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("given_name"), new ClaimSpec("family_name")));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        assertThat(credentials).hasSize(1);

        Map<String, Object> cred = credentials.get(0);
        assertThat(cred.get("format")).isEqualTo("dc+sd-jwt");

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) cred.get("meta");
        assertThat(meta.get("vct_values")).isEqualTo(List.of("IdentityCredential"));
    }

    @Test
    void build_singleMdocCredential_usesDoctype() throws Exception {
        builder.addCredentialType("mso_mdoc", "org.iso.18013.5.1.mDL", List.of(new ClaimSpec("given_name")));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        Map<String, Object> cred = credentials.get(0);

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) cred.get("meta");
        assertThat(meta.get("doctype_value")).isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void build_multipleCredentialTypes_generatesCredentialSets() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "Type1", List.of());
        builder.addCredentialType("dc+sd-jwt", "Type2", List.of());

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        assertThat(result).containsKey("credential_sets");
    }

    @Test
    void build_optionalClaims_generatesClaimSets() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt",
                "IdentityCredential",
                List.of(new ClaimSpec("given_name", false), new ClaimSpec("email", true)));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        assertThat(credentials.get(0)).containsKey("claim_sets");
    }

    @Test
    void toDcqlPath_simplePath_returnsSimpleArray() {
        List<Object> path = new ClaimSpec("given_name").toDcqlPath("dc+sd-jwt", "IdentityCredential");
        assertThat(path).containsExactly("given_name");
    }

    @Test
    void toDcqlPath_nestedPath_splitsBySlash() {
        List<Object> path = new ClaimSpec("address/street").toDcqlPath("dc+sd-jwt", "IdentityCredential");
        assertThat(path).containsExactly("address", "street");
    }

    @Test
    void toDcqlPath_mdocFormat_prependsDocType() {
        List<Object> path = new ClaimSpec("given_name").toDcqlPath("mso_mdoc", "org.iso.18013.5.1.mDL");
        assertThat(path).containsExactly("org.iso.18013.5.1.mDL", "given_name");
    }

    @Test
    void toDcqlPath_multivalued_doesNotAffectPath() {
        // multivalued only affects response-side handling, not the DCQL query path
        List<Object> sdJwt = new ClaimSpec("nationalities", false, true).toDcqlPath("dc+sd-jwt", "PID");
        assertThat(sdJwt).containsExactly("nationalities");

        List<Object> mdoc = new ClaimSpec("nationality", false, true).toDcqlPath("mso_mdoc", "eu.europa.ec.eudi.pid.1");
        assertThat(mdoc).containsExactly("eu.europa.ec.eudi.pid.1", "nationality");
    }

    @Test
    void toDcqlPath_numericSegment_parsedAsInt() {
        List<Object> path = new ClaimSpec("items/0/name").toDcqlPath("dc+sd-jwt", "Type");
        assertThat(path).containsExactly("items", 0, "name");
    }

    @Test
    void build_withTrustListUrl_includesTrustedAuthorities() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("given_name")));
        builder.setTrustListUrl("https://trust-list.example.com/tl.jwt");

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        Map<String, Object> cred = credentials.get(0);

        assertThat(cred).containsKey("trusted_authorities");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authorities = (List<Map<String, Object>>) cred.get("trusted_authorities");
        assertThat(authorities).hasSize(1);
        assertThat(authorities.get(0).get("type")).isEqualTo("etsi_tl");
        assertThat(authorities.get(0).get("values")).isEqualTo(List.of("https://trust-list.example.com/tl.jwt"));
    }

    @Test
    void build_withoutTrustListUrl_noTrustedAuthorities() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("given_name")));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        assertThat(credentials.get(0)).doesNotContainKey("trusted_authorities");
    }

    @Test
    void build_multipleCredentials_eachHasTrustedAuthorities() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "Type1", List.of());
        builder.addCredentialType("mso_mdoc", "org.iso.18013.5.1.mDL", List.of());
        builder.setTrustListUrl("https://trust-list.example.com/tl.jwt");

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        for (Map<String, Object> cred : credentials) {
            assertThat(cred).containsKey("trusted_authorities");
        }
    }

    @Test
    void fromMapperSpecs_createsBuilderCorrectly() throws Exception {
        Map<String, CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put(
                "dc+sd-jwt|IdentityCredential",
                new CredentialTypeSpec("dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("sub"))));

        DcqlQueryBuilder result = DcqlQueryBuilder.fromMapperSpecs(objectMapper, specs, false, "Test purpose", null);
        String json = result.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(json, Map.class);
        assertThat(parsed).containsKey("credentials");
    }

    @Test
    void fromMapperSpecs_withTrustListUrl_includesTrustedAuthorities() throws Exception {
        Map<String, CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put(
                "dc+sd-jwt|IdentityCredential",
                new CredentialTypeSpec("dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("sub"))));

        DcqlQueryBuilder result = DcqlQueryBuilder.fromMapperSpecs(
                objectMapper, specs, false, null, "https://trust-list.example.com/tl.jwt");
        String json = result.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) parsed.get("credentials");
        assertThat(credentials.get(0)).containsKey("trusted_authorities");
    }
}
