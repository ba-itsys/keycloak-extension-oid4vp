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
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

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
    void build_allCredentialsRequiredAndPurpose_appliesSingleCredentialSetOption() throws Exception {
        builder.setAllCredentialsRequired(true).setPurpose("Need both credentials");
        builder.addCredentialType("dc+sd-jwt", "Type1", List.of());
        builder.addCredentialType("mso_mdoc", "org.iso.18013.5.1.mDL", List.of());

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentialSets = (List<Map<String, Object>>) result.get("credential_sets");
        assertThat(credentialSets).hasSize(1);
        assertThat(credentialSets.get(0).get("purpose")).isEqualTo("Need both credentials");
        assertThat(credentialSets.get(0).get("options")).isEqualTo(List.of(List.of("cred1", "cred2")));
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
    void toDcqlPath_multivalued_appendsArraySelector() {
        List<Object> sdJwt = new ClaimSpec("nationalities", false, true).toDcqlPath("dc+sd-jwt", "PID");
        assertThat(sdJwt).containsExactly("nationalities", null);

        List<Object> mdoc = new ClaimSpec("nationality", false, true).toDcqlPath("mso_mdoc", "eu.europa.ec.eudi.pid.1");
        assertThat(mdoc).containsExactly("eu.europa.ec.eudi.pid.1", "nationality", null);
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
    void build_withAkiTrustedAuthorities_includesOnlyAki() throws Exception {
        builder.addCredentialType("dc+sd-jwt", "IdentityCredential", List.of(new ClaimSpec("given_name")));
        builder.setTrustedAuthorities("https://trust-list.example.com/tl.jwt", List.of("aki-1", "aki-2"));

        String json = builder.build();

        @SuppressWarnings("unchecked")
        Map<String, Object> result = objectMapper.readValue(json, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get("credentials");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authorities =
                (List<Map<String, Object>>) credentials.get(0).get("trusted_authorities");

        assertThat(authorities).containsExactly(Map.of("type", "aki", "values", List.of("aki-1", "aki-2")));
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

        DcqlQueryBuilder result = DcqlQueryBuilder.fromMapperSpecs(
                objectMapper, specs, false, "Test purpose", Oid4vpTrustedAuthoritiesMode.NONE, null, List.of());
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

    @Test
    void normalizeManualQuery_addsMissingMetaAndTrustedAuthorities() throws Exception {
        String manualQuery = """
                {
                  "credentials": [
                    { "id": "urn:eudi:pid:de:1", "format": "dc+sd-jwt" },
                    { "id": "eu.europa.ec.eudi.pid.1", "format": "mso_mdoc" }
                  ]
                }
                """;

        String normalized = DcqlQueryBuilder.normalizeManualQuery(
                objectMapper,
                manualQuery,
                Oid4vpTrustedAuthoritiesMode.AKI,
                "https://trust.example/tl.jwt",
                List.of("aki-1"));

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(normalized, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) parsed.get("credentials");

        assertThat(((Map<String, Object>) credentials.get(0).get("meta")).get("vct_values"))
                .isEqualTo(List.of("urn:eudi:pid:de:1"));
        assertThat(((Map<String, Object>) credentials.get(1).get("meta")).get("doctype_value"))
                .isEqualTo("eu.europa.ec.eudi.pid.1");
        assertThat(credentials.get(0).get("trusted_authorities"))
                .isEqualTo(List.of(Map.of("type", "aki", "values", List.of("aki-1"))));
    }

    @Test
    void normalizeManualQuery_preservesExistingMetaAndTrustedAuthorities() throws Exception {
        String manualQuery = """
                {
                  "credentials": [
                    {
                      "id": "urn:eudi:pid:de:1",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["custom-vct"] },
                      "trusted_authorities": [{ "type": "etsi_tl", "values": ["https://already.example/tl.jwt"] }]
                    }
                  ]
                }
                """;

        String normalized = DcqlQueryBuilder.normalizeManualQuery(
                objectMapper,
                manualQuery,
                Oid4vpTrustedAuthoritiesMode.ETSI_TL,
                "https://ignored.example/tl.jwt",
                List.of());

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(normalized, Map.class);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) parsed.get("credentials");
        Map<String, Object> credential = credentials.get(0);

        assertThat(((Map<String, Object>) credential.get("meta")).get("vct_values"))
                .isEqualTo(List.of("custom-vct"));
        assertThat(credential.get("trusted_authorities"))
                .isEqualTo(List.of(Map.of("type", "etsi_tl", "values", List.of("https://already.example/tl.jwt"))));
    }

    @Test
    void normalizeManualQuery_invalidJson_returnsOriginalString() {
        String invalid = "{not-json";

        assertThat(DcqlQueryBuilder.normalizeManualQuery(objectMapper, invalid, "https://trust.example/tl.jwt"))
                .isEqualTo(invalid);
    }

    @Test
    void aggregateFromMappers_withoutRealm_returnsEmpty() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);
        Oid4vpConfigProvider config = config("oid4vp", false, "sub", "mdoc-sub");

        assertThat(DcqlQueryBuilder.aggregateFromMappers(session, config)).isEmpty();
    }

    @Test
    void aggregateFromMappers_defaultsBlankFormatAndAddsUserMappingClaim() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "IdentityCredential");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "given_name");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.OPTIONAL, "true");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.MULTIVALUED, "true");
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getIdentityProviderMappersByAliasStream("oid4vp")).thenReturn(java.util.stream.Stream.of(mapper));
        Oid4vpConfigProvider config = config("oid4vp", false, "sub", "mdoc-sub");

        Map<String, CredentialTypeSpec> result = DcqlQueryBuilder.aggregateFromMappers(session, config);

        assertThat(result).hasSize(1);
        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.format()).isEqualTo("dc+sd-jwt");
        assertThat(type.type()).isEqualTo("IdentityCredential");
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("given_name", "sub");
        assertThat(type.claimSpecs().get(0).optional()).isTrue();
        assertThat(type.claimSpecs().get(0).multivalued()).isTrue();
    }

    @Test
    void aggregateFromMappers_usesMdocUserMappingClaimForMdocCredentials() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_FORMAT, "mso_mdoc");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "eu.europa.ec.eudi.pid.1");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "family_name");
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getIdentityProviderMappersByAliasStream("oid4vp")).thenReturn(java.util.stream.Stream.of(mapper));
        Oid4vpConfigProvider config = config("oid4vp", false, "sub", "document_number");

        Map<String, CredentialTypeSpec> result = DcqlQueryBuilder.aggregateFromMappers(session, config);

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("family_name", "document_number");
    }

    @Test
    void aggregateFromMappers_doesNotDuplicateExistingUserMappingClaim() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_FORMAT, "dc+sd-jwt");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "IdentityCredential");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "sub");
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getIdentityProviderMappersByAliasStream("oid4vp")).thenReturn(java.util.stream.Stream.of(mapper));
        Oid4vpConfigProvider config = config("oid4vp", false, "sub", "mdoc-sub");

        Map<String, CredentialTypeSpec> result = DcqlQueryBuilder.aggregateFromMappers(session, config);

        CredentialTypeSpec type = result.values().iterator().next();
        assertThat(type.claimSpecs()).extracting(ClaimSpec::path).containsExactly("sub");
    }

    @Test
    void aggregateFromMappers_ignoresBlankTypesAndHandlesMapperFailure() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        IdentityProviderMapperModel blankTypeMapper = new IdentityProviderMapperModel();
        blankTypeMapper.setConfig(new LinkedHashMap<>());
        blankTypeMapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, " ");
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getIdentityProviderMappersByAliasStream("oid4vp"))
                .thenReturn(java.util.stream.Stream.of(blankTypeMapper))
                .thenThrow(new RuntimeException("simulated mapper lookup failure"));
        Oid4vpConfigProvider config = config("oid4vp", true, "sub", "mdoc-sub");

        assertThat(DcqlQueryBuilder.aggregateFromMappers(session, config)).isEmpty();
        assertThat(DcqlQueryBuilder.aggregateFromMappers(session, config)).isEmpty();
    }

    private static Oid4vpConfigProvider config(
            String alias, boolean useIdTokenSubject, String userClaim, String mdocClaim) {
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
            public boolean isCredentialTypeAllowed(String credentialType) {
                return true;
            }

            @Override
            public String getUserMappingClaimForFormat(String format) {
                return "mso_mdoc".equals(format) ? mdocClaim : userClaim;
            }

            @Override
            public String getUserMappingClaim() {
                return userClaim;
            }

            @Override
            public String getUserMappingClaimMdoc() {
                return mdocClaim;
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
                return false;
            }

            @Override
            public int getClockSkewSeconds() {
                return 0;
            }
        };
    }
}
