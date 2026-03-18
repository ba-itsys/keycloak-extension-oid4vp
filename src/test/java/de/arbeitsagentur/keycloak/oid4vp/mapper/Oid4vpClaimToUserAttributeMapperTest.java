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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

class Oid4vpClaimToUserAttributeMapperTest {

    private final Oid4vpClaimToUserAttributeMapper mapper = new Oid4vpClaimToUserAttributeMapper();

    @Test
    void metadataAndConfigProperties_areExposed() {
        List<ProviderConfigProperty> properties = mapper.getConfigProperties();

        assertThat(mapper.getId()).isEqualTo(Oid4vpClaimToUserAttributeMapper.PROVIDER_ID);
        assertThat(mapper.getDisplayCategory()).isEqualTo("Attribute Importer");
        assertThat(mapper.getDisplayType()).isEqualTo("OID4VP Claim to User Attribute");
        assertThat(mapper.getHelpText()).contains("verifiable credential");
        assertThat(mapper.getCompatibleProviders()).containsExactly("oid4vp");
        assertThat(mapper.supportsSyncMode(IdentityProviderSyncMode.LEGACY)).isTrue();
        assertThat(properties)
                .extracting(ProviderConfigProperty::getName)
                .contains(
                        "credential.format",
                        "credential.type",
                        "claim",
                        "multivalued",
                        "optional",
                        Oid4vpClaimToUserAttributeMapper.USER_ATTRIBUTE);
    }

    @Test
    void preprocessFederatedIdentity_mapsStandardAttributesAndCustomAttributes() {
        BrokeredIdentityContext context = contextWithClaims(
                Map.of("email", "alice@example.org", "profile", Map.of("roles", List.of("admin", "user"))));

        mapper.preprocessFederatedIdentity(null, null, mapperModel("email", "email", false), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("profile/roles", "departmentRoles", false), context);

        assertThat(context.getEmail()).isEqualTo("alice@example.org");
        assertThat(context.getAttributes().get("departmentRoles")).containsExactly("admin", "user");
    }

    @Test
    void preprocessFederatedIdentity_ignoresMissingRequiredClaimWhenOptional() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("given_name", "Alice"));

        mapper.preprocessFederatedIdentity(null, null, mapperModel("family_name", "lastName", true), context);

        assertThat(context.getLastName()).isNull();
    }

    @Test
    void preprocessFederatedIdentity_skipsMismatchedCredentialFilter() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("email", "alice@example.org"));
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_TYPE_KEY, "MDOC");

        IdentityProviderMapperModel mapperModel = mapperModel("email", "email", false);
        mapperModel.getConfig().put("credential.format", "dc+sd-jwt");

        mapper.preprocessFederatedIdentity(null, null, mapperModel, context);

        assertThat(context.getEmail()).isNull();
    }

    @Test
    void updateBrokeredUser_mapsStandardAndCustomAttributes() {
        BrokeredIdentityContext context =
                contextWithClaims(Map.of("given_name", "Alice", "groups", List.of("blue", "green")));
        UserModel user = mock(UserModel.class);

        mapper.updateBrokeredUser(null, null, user, mapperModel("given_name", "firstName", false), context);
        mapper.updateBrokeredUser(null, null, user, mapperModel("groups", "teamNames", false), context);

        verify(user).setFirstName("Alice");
        verify(user).setAttribute("teamNames", List.of("blue", "green"));
    }

    @Test
    void importNewUser_mapsStandardAndCustomAttributes() {
        BrokeredIdentityContext context =
                contextWithClaims(Map.of("given_name", "Alice", "groups", List.of("blue", "green")));
        UserModel user = mock(UserModel.class);

        mapper.importNewUser(null, null, user, mapperModel("given_name", "firstName", false), context);
        mapper.importNewUser(null, null, user, mapperModel("groups", "teamNames", false), context);

        verify(user).setFirstName("Alice");
        verify(user).setAttribute("teamNames", List.of("blue", "green"));
    }

    @Test
    void updateBrokeredUser_skipsWhenClaimOrAttributeIsMissing() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("given_name", "Alice"));
        UserModel user = mock(UserModel.class);

        mapper.updateBrokeredUser(null, null, user, mapperModel("", "firstName", false), context);
        mapper.updateBrokeredUser(null, null, user, mapperModel("given_name", "", false), context);

        verifyNoInteractions(user);
    }

    private static BrokeredIdentityContext contextWithClaims(Map<String, Object> claims) {
        IdentityProviderModel identityProvider = new IdentityProviderModel();
        identityProvider.setAlias("oid4vp");
        identityProvider.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("broker-user", identityProvider);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_TYPE_KEY, "SD_JWT");
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY, "eu.europa.ec.eudi.pid.1");
        return context;
    }

    private static IdentityProviderMapperModel mapperModel(String claimPath, String attribute, boolean optional) {
        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        Map<String, String> config = new HashMap<>();
        config.put("claim", claimPath);
        config.put(Oid4vpClaimToUserAttributeMapper.USER_ATTRIBUTE, attribute);
        config.put("optional", String.valueOf(optional));
        mapperModel.setConfig(config);
        return mapperModel;
    }
}
