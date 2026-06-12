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
import org.keycloak.sessions.AuthenticationSessionModel;

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
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        context.setAuthenticationSession(authenticationSession);

        mapper.preprocessFederatedIdentity(null, null, mapperModel("issuer", "issuer_note", false), context);

        verify(authenticationSession).setUserSessionNote("issuer_note", "https://issuer.example");
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
    void updateBrokeredUser_setsSessionNoteWithoutTouchingUser() {
        UserModel user = mock(UserModel.class);
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        BrokeredIdentityContext context = contextWithClaims(Map.of("issuer", "https://issuer.example"));
        context.setAuthenticationSession(authenticationSession);

        mapper.updateBrokeredUser(null, null, user, mapperModel("issuer", "issuer_note", false), context);

        verify(authenticationSession).setUserSessionNote("issuer_note", "https://issuer.example");
        verifyNoInteractions(user);
    }

    @Test
    void importNewUser_storesSessionNoteInContextWhenNoAuthenticationSessionExists() {
        BrokeredIdentityContext context = contextWithClaims(Map.of("issuer", "https://issuer.example"));

        mapper.importNewUser(null, null, mock(UserModel.class), mapperModel("issuer", "issuer_note", false), context);

        UserSessionModel userSession = mock(UserSessionModel.class);
        context.addSessionNotesToUserSession(userSession);

        verify(userSession).setNote("issuer_note", "https://issuer.example");
    }

    @Test
    void preprocessFederatedIdentity_mdocNestedClaimParsesJsonBaseValue() {
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        BrokeredIdentityContext context = contextWithClaims(
                Map.of("eu.europa.ec.eudi.pid.1/birth_place", "{\"locality\":\"BERLIN\"}"),
                "MDOC",
                "eu.europa.ec.eudi.pid.1");
        context.setAuthenticationSession(authenticationSession);

        mapper.preprocessFederatedIdentity(
                null, null, mapperModel("birth_place/locality", "birth_place_note", false), context);

        verify(authenticationSession).setUserSessionNote("birth_place_note", "BERLIN");
    }

    @Test
    void preprocessFederatedIdentity_mdocNestedClaimPrefersNamespacedObjectOverScalarShadow() {
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        BrokeredIdentityContext context = contextWithClaims(
                Map.of(
                        "birth_place",
                        "RAW-SCALAR",
                        "eu.europa.ec.eudi.pid.1/birth_place",
                        Map.of("locality", "BERLIN")),
                "MDOC",
                "eu.europa.ec.eudi.pid.1");
        context.setAuthenticationSession(authenticationSession);

        mapper.preprocessFederatedIdentity(
                null, null, mapperModel("birth_place/locality", "birth_place_note", false), context);

        verify(authenticationSession).setUserSessionNote("birth_place_note", "BERLIN");
    }

    @Test
    void preprocessFederatedIdentity_mdocMultivaluedClaimFallsBackToSingleScalarValue() {
        AuthenticationSessionModel authenticationSession = mock(AuthenticationSessionModel.class);
        BrokeredIdentityContext context = contextWithClaims(
                Map.of("eu.europa.ec.eudi.pid.1/nationality", "DE"), "MDOC", "eu.europa.ec.eudi.pid.1");
        context.setAuthenticationSession(authenticationSession);

        mapper.preprocessFederatedIdentity(
                null, null, mapperModel("nationality", "nationality_note", false, true), context);

        verify(authenticationSession).setUserSessionNote("nationality_note", "DE");
    }

    private static BrokeredIdentityContext contextWithClaims(Map<String, Object> claims) {
        return contextWithClaims(claims, "SD_JWT", "eu.europa.ec.eudi.pid.1");
    }

    private static BrokeredIdentityContext contextWithClaims(
            Map<String, Object> claims, String presentationType, String credentialType) {
        IdentityProviderModel identityProvider = new IdentityProviderModel();
        identityProvider.setAlias("oid4vp");
        identityProvider.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("broker-user", identityProvider);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_TYPE_KEY, presentationType);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY, credentialType);
        return context;
    }

    private static IdentityProviderMapperModel mapperModel(String claimPath, String sessionNote, boolean optional) {
        return mapperModel(claimPath, sessionNote, optional, false);
    }

    private static IdentityProviderMapperModel mapperModel(
            String claimPath, String sessionNote, boolean optional, boolean multivalued) {
        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        Map<String, String> config = new HashMap<>();
        config.put("claim", claimPath);
        config.put(Oid4vpClaimToUserSessionMapper.SESSION_NOTE, sessionNote);
        config.put("optional", String.valueOf(optional));
        config.put("multivalued", String.valueOf(multivalued));
        mapperModel.setConfig(config);
        return mapperModel;
    }
}
