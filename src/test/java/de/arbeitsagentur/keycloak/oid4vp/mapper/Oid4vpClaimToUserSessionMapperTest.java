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
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

class Oid4vpClaimToUserSessionMapperTest {

    private final Oid4vpClaimToUserSessionMapper mapper = new Oid4vpClaimToUserSessionMapper();

    @Test
    void metadataAndConfigProperties_areExposed() {
        List<ProviderConfigProperty> properties = mapper.getConfigProperties();

        assertThat(mapper.getId()).isEqualTo(Oid4vpClaimToUserSessionMapper.PROVIDER_ID);
        assertThat(mapper.getDisplayCategory()).isEqualTo("Token Mapper");
        assertThat(mapper.getDisplayType()).isEqualTo("OID4VP Claim to User Session");
        assertThat(mapper.getHelpText()).contains("session note");
        assertThat(mapper.getCompatibleProviders()).containsExactly("oid4vp");
        assertThat(mapper.supportsSyncMode(IdentityProviderSyncMode.FORCE)).isTrue();
        assertThat(properties)
                .extracting(ProviderConfigProperty::getName)
                .contains(
                        "credential.format",
                        "credential.type",
                        "claim",
                        "multivalued",
                        "optional",
                        Oid4vpClaimToUserSessionMapper.SESSION_NOTE);
    }

    @Test
    void preprocessFederatedIdentity_setsSessionNoteFromClaim() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("issuer", "https://issuer.example"));

        mapper.preprocessFederatedIdentity(null, null, mapperModel("issuer", "issuer_note", false), context);

        UserSessionModel userSession = mock(UserSessionModel.class);
        context.addSessionNotesToUserSession(userSession);
        verify(userSession).setNote("issuer_note", "https://issuer.example");
    }

    @Test
    void preprocessFederatedIdentity_skipsMissingOptionalClaimAndFilterMismatches() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("issuer", "https://issuer.example"));
        IdentityProviderMapperModel optionalMissing = mapperModel("missing", "issuer_note", true);
        IdentityProviderMapperModel wrongFormat = mapperModel("issuer", "issuer_note", false);
        wrongFormat.getConfig().put("credential.format", "mso_mdoc");

        mapper.preprocessFederatedIdentity(null, null, optionalMissing, context);
        mapper.preprocessFederatedIdentity(null, null, wrongFormat, context);

        UserSessionModel userSession = mock(UserSessionModel.class);
        context.addSessionNotesToUserSession(userSession);
        verifyNoInteractions(userSession);
    }

    @Test
    void updateBrokeredUser_isNoOp() {
        UserModel user = mock(UserModel.class);

        mapper.updateBrokeredUser(
                null, null, user, mapperModel("issuer", "issuer_note", false), contextWithClaims(Map.of()));

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

    private static IdentityProviderMapperModel mapperModel(String claimPath, String sessionNote, boolean optional) {
        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        Map<String, String> config = new HashMap<>();
        config.put("claim", claimPath);
        config.put(Oid4vpClaimToUserSessionMapper.SESSION_NOTE, sessionNote);
        config.put("optional", String.valueOf(optional));
        mapperModel.setConfig(config);
        return mapperModel;
    }
}
