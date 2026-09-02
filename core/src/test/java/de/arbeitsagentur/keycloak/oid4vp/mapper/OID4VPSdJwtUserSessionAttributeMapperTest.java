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

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;

/**
 * Mirrors the test cases of upstream Keycloak's {@code OID4VPSdJwtUserSessionAttributeMapperTest}.
 */
class OID4VPSdJwtUserSessionAttributeMapperTest {

    private final OID4VPSdJwtUserSessionAttributeMapper mapper = new OID4VPSdJwtUserSessionAttributeMapper();

    @Test
    void importsStringClaimAsSessionNote() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"vct": "https://credentials.example.com/identity"}""");

        importNewUser(context, "vct", "credential_vct");

        assertThat(sessionNote(context, "credential_vct")).isEqualTo("https://credentials.example.com/identity");
    }

    @Test
    void importsNestedAndArrayClaims() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"address": {"locality": "London"}, "nationalities": ["DE", "CZ"]}""");

        importNewUser(context, "address.locality", "locality");
        importNewUser(context, "nationalities", "nationalities");

        assertThat(sessionNote(context, "locality")).isEqualTo("London");
        assertThat(sessionNote(context, "nationalities")).isEqualTo("DE,CZ");
    }

    @Test
    void importsObjectClaimAsJson() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"address": {"locality": "London"}}""");

        importNewUser(context, "address", "addressJson");

        assertThat(sessionNote(context, "addressJson")).isEqualTo("{\"locality\":\"London\"}");
    }

    @Test
    void missingClaimSetsNoNote() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"vct": "identity"}""");

        importNewUser(context, "phone", "phone");

        assertThat(sessionNote(context, "phone")).isNull();
    }

    @Test
    void blankConfigurationSetsNoNote() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"vct": "identity"}""");

        importNewUser(context, "", "note");
        importNewUser(context, "vct", "");

        assertThat(sessionNote(context, "note")).isNull();
        assertThat(sessionNote(context, "")).isNull();
    }

    @Test
    void updateBrokeredUserAlsoSetsTheNote() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"vct": "identity"}""");

        mapper.updateBrokeredUser(null, null, null, model("vct", "credential_vct"), context);

        assertThat(sessionNote(context, "credential_vct")).isEqualTo("identity");
    }

    // The note is per login state, so it must also be set on the preprocess path, which runs for
    // existing users whose effective sync mode skips updateBrokeredUser.
    @Test
    void preprocessFederatedIdentityAlsoSetsTheNote() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"vct": "identity"}""");

        mapper.preprocessFederatedIdentity(null, null, model("vct", "credential_vct"), context);

        assertThat(sessionNote(context, "credential_vct")).isEqualTo("identity");
    }

    @Test
    void supportsAllSyncModes() {
        for (IdentityProviderSyncMode syncMode : IdentityProviderSyncMode.values()) {
            assertThat(mapper.supportsSyncMode(syncMode)).isTrue();
        }
    }

    @Test
    void isCompatibleWithTheOid4vpProvider() {
        assertThat(mapper.getCompatibleProviders()).containsExactly("oid4vp");
    }

    private void importNewUser(BrokeredIdentityContext context, String claimPath, String attribute) {
        mapper.importNewUser(null, null, null, model(claimPath, attribute), context);
    }

    private static IdentityProviderMapperModel model(String claimPath, String attribute) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, claimPath);
        config.put(OID4VPSdJwtUserSessionAttributeMapper.ATTRIBUTE, attribute);
        config.put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, "urn:eudi:pid:1");
        model.setConfig(config);
        return model;
    }

    // Without an authentication session the context stores session notes in its context data.
    @SuppressWarnings("unchecked")
    private static String sessionNote(BrokeredIdentityContext context, String name) {
        Map<String, String> notes =
                (Map<String, String>) context.getContextData().get(Constants.MAPPER_SESSION_NOTES);
        return notes == null ? null : notes.get(name);
    }

    private static BrokeredIdentityContext contextWithClaims(String claimsJson) throws Exception {
        return OID4VPSdJwtUserAttributeMapperTest.contextWithClaims(claimsJson);
    }
}
