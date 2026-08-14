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
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthorityType;
import de.arbeitsagentur.keycloak.oid4vp.mapper.AbstractOID4VPClaimMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserAttributeMapper;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderMapperModel;

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
                "dc+sd-jwt",
                "IdentityCredential",
                List.of(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("family_name")));

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
        builder.addCredentialType(
                "mso_mdoc", "org.iso.18013.5.1.mDL", List.of(ClaimSpec.mdoc("org.iso.18013.5.1", "given_name")));

        Map<String, Object> cred = firstCredential(builder.build());

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) cred.get("meta");
        assertThat(meta.get("doctype_value")).isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void build_claimSetIds_generatesOneOptionPerIdInLexicographicOrder() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt",
                "IdentityCredential",
                List.of(
                        ClaimSpec.sdJwt("given_name", List.of("1-full")),
                        ClaimSpec.sdJwt("family_name", List.of("2-min", "1-full")),
                        ClaimSpec.sdJwt("birthdate")));

        Map<String, Object> credential = firstCredential(builder.build());

        assertThat(credential.get("claim_sets"))
                .isEqualTo(List.of(List.of("claim1", "claim2", "claim3"), List.of("claim2", "claim3")));
    }

    @Test
    void build_claimSetIds_untaggedClaimsJoinEveryOption() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt",
                "IdentityCredential",
                List.of(
                        ClaimSpec.sdJwt("email", List.of("contact")),
                        ClaimSpec.sdJwt("phone", List.of("phone-only")),
                        ClaimSpec.sdJwt("sub")));

        Map<String, Object> credential = firstCredential(builder.build());

        assertThat(credential.get("claim_sets"))
                .isEqualTo(List.of(List.of("claim1", "claim3"), List.of("claim2", "claim3")));
    }

    @Test
    void build_noClaimSetIds_omitsClaimSets() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("given_name"), ClaimSpec.sdJwt("email")));

        Map<String, Object> credential = firstCredential(builder.build());

        assertThat(credential).doesNotContainKey("claim_sets");
    }

    @Test
    void build_claimSetIds_onlyAffectCredentialDefiningThem() throws Exception {
        builder.addCredentialType(
                "dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("given_name", List.of("min"))));
        builder.addCredentialType(
                "mso_mdoc",
                "eu.europa.ec.eudi.pid.1",
                List.of(ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "family_name")));

        String json = builder.build();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");

        assertThat(credentials.get(0)).containsKey("claim_sets");
        assertThat(credentials.get(1)).doesNotContainKey("claim_sets");
    }

    @Test
    void toDcqlPath_mapsClaimPathStepsToPointer() {
        assertThat(ClaimSpec.sdJwt("given_name").toDcqlPath()).containsExactly("given_name");
        assertThat(ClaimSpec.sdJwt("address.street_address").toDcqlPath()).containsExactly("address", "street_address");
        assertThat(ClaimSpec.sdJwt("nationalities[]").toDcqlPath()).isEqualTo(Arrays.asList("nationalities", null));
        assertThat(ClaimSpec.sdJwt("degrees[0].type").toDcqlPath()).containsExactly("degrees", 0, "type");
    }

    @Test
    void toDcqlPath_mdocPathIsNamespaceAndElement() {
        assertThat(ClaimSpec.mdoc("org.iso.18013.5.1", "given_name").toDcqlPath())
                .containsExactly("org.iso.18013.5.1", "given_name");
        assertThat(ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "birth_place.locality")
                        .toDcqlPath())
                .as("mDoc claims cannot be requested below element level")
                .containsExactly("eu.europa.ec.eudi.pid.1", "birth_place");
    }

    @Test
    void toDcqlPath_invalidPath_isEmpty() {
        assertThat(ClaimSpec.sdJwt("degrees[x]").toDcqlPath()).isEmpty();
    }

    @Test
    void build_withTrustListUrl_includesTrustedAuthorities() throws Exception {
        builder.addCredentialType("pid", "dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("given_name")));
        builder.setTrustedAuthorities(Map.of(
                "pid",
                TrustedAuthority.of(TrustedAuthorityType.ETSI_TL, List.of("https://trust-list.example.com/tl.jwt"))));

        Map<String, Object> cred = firstCredential(builder.build());

        assertThat(cred).containsKey("trusted_authorities");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authorities = (List<Map<String, Object>>) cred.get("trusted_authorities");
        assertThat(authorities).hasSize(1);
        assertThat(authorities.get(0).get("type")).isEqualTo("etsi_tl");
        assertThat(authorities.get(0).get("values")).isEqualTo(List.of("https://trust-list.example.com/tl.jwt"));
    }

    @Test
    void build_withSeveralAuthorityTypes_writesThemAsAlternatives() throws Exception {
        builder.addCredentialType("pid", "dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("given_name")));
        builder.setTrustedAuthorities(Map.of(
                "pid",
                List.of(
                        new TrustedAuthority(
                                TrustedAuthorityType.ETSI_TL, List.of("https://trust-list.example.com/tl.jwt")),
                        new TrustedAuthority(TrustedAuthorityType.AKI, List.of("aki-1", "aki-2")))));

        Map<String, Object> cred = firstCredential(builder.build());

        assertThat(cred.get("trusted_authorities"))
                .isEqualTo(List.of(
                        Map.of("type", "etsi_tl", "values", List.of("https://trust-list.example.com/tl.jwt")),
                        Map.of("type", "aki", "values", List.of("aki-1", "aki-2"))));
    }

    @Test
    void build_withoutTrustedAuthorities_omitsTheMember() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("given_name")));

        assertThat(firstCredential(builder.build())).doesNotContainKey("trusted_authorities");
    }

    @Test
    void build_credentialsOfDifferentTrustDomains_carryTheirOwnAuthorities() throws Exception {
        builder.addCredentialType("pid", "dc+sd-jwt", "urn:eudi:pid:1", List.of());
        builder.addCredentialType("badge", "dc+sd-jwt", "https://kc.example/badge", List.of());
        builder.setTrustedAuthorities(Map.of(
                "pid",
                TrustedAuthority.of(TrustedAuthorityType.ETSI_TL, List.of("https://trust-list.example.com/tl.jwt")),
                "badge",
                List.of()));

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(builder.build(), Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");

        assertThat(credentials).hasSize(2);
        assertThat(credentials.get(0).get("id")).isEqualTo("pid");
        assertThat(credentials.get(0)).containsKey("trusted_authorities");
        assertThat(credentials.get(1).get("id")).isEqualTo("badge");
        assertThat(credentials.get(1))
                .as("a credential of a trust domain with nothing to advertise stays unconstrained")
                .doesNotContainKey("trusted_authorities");
    }

    @Test
    void fromMapperSpecs_createsBuilderCorrectly() throws Exception {
        Map<String, CredentialTypeSpec> specs = new LinkedHashMap<>();
        specs.put(
                "dc+sd-jwt|IdentityCredential",
                new CredentialTypeSpec("dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("sub"))));

        DcqlQueryBuilder result = DcqlQueryBuilder.fromMapperSpecs(objectMapper, specs, List.of(), Map.of());
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
                new CredentialTypeSpec("dc+sd-jwt", "IdentityCredential", List.of(ClaimSpec.sdJwt("sub"))));

        DcqlQueryBuilder result = DcqlQueryBuilder.fromMapperSpecs(
                objectMapper,
                specs,
                List.of(),
                Map.of(
                        "dc+sd-jwt|IdentityCredential",
                        TrustedAuthority.of(
                                TrustedAuthorityType.ETSI_TL, List.of("https://trust-list.example.com/tl.jwt"))));

        assertThat(firstCredential(result.build())).containsKey("trusted_authorities");
    }

    @Test
    void aggregateFromMappers_withoutMappers_returnsEmpty() {
        assertThat(aggregate(Stream.of(), config("oid4vp", false, "sub"))).isEmpty();
    }

    @Test
    void aggregateFromMappers_readsSdJwtMapperAndAddsPrincipalClaim() {
        IdentityProviderMapperModel mapper = sdJwtMapper("IdentityCredential", "given_name", " 1-full , 2-min ");

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, "sub"));

        assertThat(result).hasSize(1);
        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.format()).isEqualTo("dc+sd-jwt");
        assertThat(type.type()).isEqualTo("IdentityCredential");
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("given_name", "sub");
        assertThat(type.claimSpecs().get(0).claimSetIds()).containsExactly("1-full", "2-min");
        assertThat(type.claimSpecs().get(1).claimSetIds())
                .as("auto-added principal claim must be part of every claim set")
                .isEmpty();
    }

    @Test
    void aggregateFromMappers_readsMdocMapperWithNamespaceAndPrincipal() {
        IdentityProviderMapperModel mapper = mdocMapper("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "family_name");

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, "given_name"));

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.format()).isEqualTo("mso_mdoc");
        assertThat(type.claimSpecs())
                .containsExactly(
                        ClaimSpec.mdoc("org.iso.18013.5.1", "family_name"),
                        ClaimSpec.mdoc("org.iso.18013.5.1", "given_name"));
    }

    @Test
    void aggregateFromMappers_mdocNamespaceDefaultsToDoctype() {
        IdentityProviderMapperModel mapper = mdocMapper("eu.europa.ec.eudi.pid.1", null, "family_name");

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, "family_name"));

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.claimSpecs()).containsExactly(ClaimSpec.mdoc("eu.europa.ec.eudi.pid.1", "family_name"));
    }

    @Test
    void aggregateFromMappers_doesNotDuplicateExistingPrincipalClaim() {
        IdentityProviderMapperModel mapper = sdJwtMapper("IdentityCredential", "sub", null);

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, "sub"));

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("sub");
    }

    @Test
    void aggregateFromMappers_transientUsersEnabled_skipsPrincipalClaim() {
        IdentityProviderMapperModel mapper = sdJwtMapper("IdentityCredential", "given_name", null);

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, true, "sub"));

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("given_name");
    }

    @Test
    void aggregateFromMappers_skipsForeignAndMisconfiguredMappers() {
        IdentityProviderMapperModel foreign = new IdentityProviderMapperModel();
        foreign.setIdentityProviderMapper("hardcoded-attribute-idp-mapper");
        foreign.setConfig(new LinkedHashMap<>());

        IdentityProviderMapperModel blankType = sdJwtMapper(" ", "given_name", null);
        IdentityProviderMapperModel invalidPath = sdJwtMapper("IdentityCredential", "degrees[x]", null);

        assertThat(aggregate(Stream.of(foreign, blankType, invalidPath), config("oid4vp", true, "sub")))
                .isEmpty();
    }

    @Test
    void aggregateFromMappers_duplicateCredentialIdAcrossCredentialTypes_isReported() {
        IdentityProviderMapperModel pid = sdJwtMapper("urn:eudi:pid:1", "family_name", null, "shared");
        IdentityProviderMapperModel other = sdJwtMapper("urn:eudi:diploma:1", "family_name", null, "shared");

        DcqlQueryBuilder.AggregatedCredentials aggregated =
                DcqlQueryBuilder.aggregateFromMappers(Stream.of(pid, other), config("oid4vp", false, "family_name"));

        assertThat(aggregated.problems())
                .as("a credential id addresses exactly one credential")
                .singleElement()
                .asString()
                .contains("shared", "urn:eudi:pid:1", "urn:eudi:diploma:1");
    }

    @Test
    void aggregateFromMappers_sameCredentialIdForTheSameCredentialType_isOneCredential() {
        IdentityProviderMapperModel first = sdJwtMapper("urn:eudi:pid:1", "family_name", null, "pid");
        IdentityProviderMapperModel second = sdJwtMapper("urn:eudi:pid:1", "given_name", null, "pid");

        DcqlQueryBuilder.AggregatedCredentials aggregated =
                DcqlQueryBuilder.aggregateFromMappers(Stream.of(first, second), config("oid4vp", false, "family_name"));

        assertThat(aggregated.problems()).isEmpty();
        assertThat(aggregated.credentials()).containsOnlyKeys("pid");
        assertThat(aggregated.credentials().get("pid").claimSpecs())
                .extracting(ClaimSpec::path)
                .contains("family_name", "given_name");
    }

    @Test
    void aggregateFromMappers_ordersCredentialsByCredentialId() {
        IdentityProviderMapperModel mdocMapper = mdocMapper("eu.europa.ec.eudi.pid.1", null, "family_name");
        IdentityProviderMapperModel sdJwtMapper = sdJwtMapper("urn:eudi:pid:1", "family_name", null);

        Map<String, CredentialTypeSpec> result =
                aggregate(Stream.of(mdocMapper, sdJwtMapper), config("oid4vp", false, "family_name"));

        assertThat(result.keySet())
                .as("credential order must not depend on mapper enumeration order")
                .containsExactly("mdoc_eu_europa_ec_eudi_pid_1", "sdjwt_urn_eudi_pid_1");
    }

    @Test
    void aggregateFromMappers_blankCredentialId_derivesFormatPrefixedSlug() {
        IdentityProviderMapperModel sdJwt = sdJwtMapper("urn:eudi:pid:1", "family_name", null);
        IdentityProviderMapperModel mdoc = mdocMapper("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "family_name");

        Map<String, CredentialTypeSpec> result =
                aggregate(Stream.of(sdJwt, mdoc), config("oid4vp", false, "family_name"));

        assertThat(result)
                .as("credential ids must be stable across mapper changes, not positional")
                .containsOnlyKeys("sdjwt_urn_eudi_pid_1", "mdoc_org_iso_18013_5_1_mDL");
    }

    @Test
    void aggregateFromMappers_explicitCredentialId_isUsedAsQueryId() {
        IdentityProviderMapperModel mapper = sdJwtMapper("urn:eudi:pid:1", "family_name", null, "pid");

        Map<String, CredentialTypeSpec> result = aggregate(Stream.of(mapper), config("oid4vp", false, "family_name"));

        assertThat(result).containsOnlyKeys("pid");
    }

    @Test
    void aggregateFromMappers_sameTypeDifferentCredentialIds_producesTwoEntries() {
        IdentityProviderMapperModel full = sdJwtMapper("urn:eudi:pid:1", "given_name", null, "pid_full");
        IdentityProviderMapperModel minimal = sdJwtMapper("urn:eudi:pid:1", "family_name", null, "pid_minimal");

        Map<String, CredentialTypeSpec> result =
                aggregate(Stream.of(full, minimal), config("oid4vp", false, "family_name"));

        assertThat(result)
                .as("the credential id is the grouping key, so one type can be requested twice")
                .containsOnlyKeys("pid_full", "pid_minimal");
        assertThat(result.get("pid_full").claimSpecs())
                .extracting(ClaimSpec::path)
                .contains("given_name");
        assertThat(result.get("pid_minimal").claimSpecs())
                .extracting(ClaimSpec::path)
                .doesNotContain("given_name");
    }

    @Test
    void build_credentialSets_emittedVerbatim() throws Exception {
        builder.addCredentialType("pid", "dc+sd-jwt", "urn:eudi:pid:1", List.of());
        builder.addCredentialType("mdl", "mso_mdoc", "org.iso.18013.5.1.mDL", List.of());
        builder.setCredentialSets(
                List.of(new CredentialSet(List.of(List.of("pid", "mdl"), List.of("pid")), true, "Login")));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentialSets = (List<Map<String, Object>>) result.get("credential_sets");
        assertThat(credentialSets).hasSize(1);
        assertThat(credentialSets.get(0).get("options")).isEqualTo(List.of(List.of("pid", "mdl"), List.of("pid")));
        assertThat(credentialSets.get(0).get("purpose")).isEqualTo("Login");
        assertThat(credentialSets.get(0))
                .as("required defaults to true in DCQL, so it is only written when false")
                .doesNotContainKey("required");
    }

    @Test
    void build_optionalCredentialSet_writesRequiredFalse() throws Exception {
        builder.addCredentialType("mdl", "mso_mdoc", "org.iso.18013.5.1.mDL", List.of());
        builder.setCredentialSets(List.of(new CredentialSet(List.of(List.of("mdl")), false, null)));

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(builder.build(), Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentialSets = (List<Map<String, Object>>) result.get("credential_sets");
        assertThat(credentialSets.get(0).get("required")).isEqualTo(false);
    }

    @Test
    void build_withoutCredentialSets_omitsCredentialSets() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "Type1", List.of());
        builder.addCredentialType("mso_mdoc", "org.iso.18013.5.1.mDL", List.of());

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(builder.build(), Map.class);

        assertThat(result)
                .as("no credential_sets means the DCQL default: every credential is required")
                .doesNotContainKey("credential_sets");
    }

    @Test
    void build_addCredentialTypeWithoutId_derivesTheSameSlugAsTheAggregation() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "urn:eudi:pid:1", List.of());

        assertThat(firstCredential(builder.build()).get("id")).isEqualTo("sdjwt_urn_eudi_pid_1");
    }

    private static Map<String, CredentialTypeSpec> aggregate(
            Stream<IdentityProviderMapperModel> mappers, Oid4vpConfigProvider config) {
        return DcqlQueryBuilder.aggregateFromMappers(mappers, config).credentials();
    }

    private static IdentityProviderMapperModel sdJwtMapper(String vct, String claim, String claimSetIds) {
        return sdJwtMapper(vct, claim, claimSetIds, null);
    }

    private static IdentityProviderMapperModel sdJwtMapper(
            String vct, String claim, String claimSetIds, String credentialId) {
        IdentityProviderMapperModel mapper = sdJwtMapperWithoutId(vct, claim, claimSetIds);
        if (credentialId != null) {
            mapper.getConfig().put(AbstractOID4VPClaimMapper.CREDENTIAL_ID, credentialId);
        }
        return mapper;
    }

    private static IdentityProviderMapperModel sdJwtMapperWithoutId(String vct, String claim, String claimSetIds) {
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setIdentityProviderMapper(OID4VPSdJwtUserAttributeMapper.PROVIDER_ID);
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, vct);
        mapper.getConfig().put(AbstractOID4VPClaimMapper.CLAIM, claim);
        if (claimSetIds != null) {
            mapper.getConfig().put(AbstractOID4VPClaimMapper.CLAIM_SET_IDS, claimSetIds);
        }
        return mapper;
    }

    private static IdentityProviderMapperModel mdocMapper(String doctype, String namespace, String claim) {
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setIdentityProviderMapper(OID4VPMdocUserAttributeMapper.PROVIDER_ID);
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, doctype);
        mapper.getConfig().put(AbstractOID4VPClaimMapper.CLAIM, claim);
        if (namespace != null) {
            mapper.getConfig().put(OID4VPMdocUserAttributeMapper.NAMESPACE, namespace);
        }
        return mapper;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> firstCredential(String dcqlJson) throws Exception {
        Map<String, Object> result = objectMapper.readValue(dcqlJson, Map.class);
        return ((List<Map<String, Object>>) result.get("credentials")).get(0);
    }

    private static Oid4vpConfigProvider config(String alias, boolean useIdTokenSubject, String principal) {
        return config(alias, useIdTokenSubject, false, principal);
    }

    private static Oid4vpConfigProvider config(
            String alias, boolean useIdTokenSubject, boolean transientUsersEnabled, String principal) {
        return new Oid4vpConfigProvider() {
            @Override
            public String getAlias() {
                return alias;
            }

            @Override
            public boolean isIssuerAllowed(String issuer) {
                return true;
            }

            @Override
            public String getPrincipalAttribute() {
                return principal;
            }

            @Override
            public String getPrincipalCredentialId() {
                return null;
            }

            @Override
            public int getSsePollIntervalMs() {
                return 0;
            }

            @Override
            public int getSseTimeoutSeconds() {
                return 0;
            }

            @Override
            public int getSsePingIntervalSeconds() {
                return 0;
            }

            @Override
            public int getCrossDeviceCompleteTtlSeconds() {
                return 0;
            }

            @Override
            public boolean isUseIdTokenSubject() {
                return useIdTokenSubject;
            }

            @Override
            public boolean isTransientUsersEnabled() {
                return transientUsersEnabled;
            }

            @Override
            public int getClockSkewSeconds() {
                return 0;
            }
        };
    }
}
