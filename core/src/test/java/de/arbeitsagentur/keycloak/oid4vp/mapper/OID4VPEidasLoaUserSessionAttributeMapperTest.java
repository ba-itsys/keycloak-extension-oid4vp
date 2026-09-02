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

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;

class OID4VPEidasLoaUserSessionAttributeMapperTest {

    private final OID4VPEidasLoaUserSessionAttributeMapper mapper = new OID4VPEidasLoaUserSessionAttributeMapper();

    @Test
    void sameDeviceCompletionStoresTheHigherDefaultLevel() {
        BrokeredIdentityContext context = contextWithFlow(Oid4vpConstants.FLOW_SAME_DEVICE);

        mapper.importNewUser(null, null, null, model(Map.of()), context);

        assertThat(sessionNote(context, "eidas_loa")).isEqualTo("STORK-QAA-Level-4");
    }

    @Test
    void crossDeviceCompletionStoresTheLowerDefaultLevel() {
        BrokeredIdentityContext context = contextWithFlow(Oid4vpConstants.FLOW_CROSS_DEVICE);

        mapper.importNewUser(null, null, null, model(Map.of()), context);

        assertThat(sessionNote(context, "eidas_loa")).isEqualTo("STORK-QAA-Level-3");
    }

    @Test
    void configuredAttributeAndLevelsOverrideTheDefaults() {
        BrokeredIdentityContext context = contextWithFlow(Oid4vpConstants.FLOW_CROSS_DEVICE);

        mapper.importNewUser(
                null,
                null,
                null,
                model(Map.of(
                        OID4VPEidasLoaUserSessionAttributeMapper.ATTRIBUTE, "acr",
                        OID4VPEidasLoaUserSessionAttributeMapper.SAME_DEVICE_LOA, "http://eidas.europa.eu/LoA/high",
                        OID4VPEidasLoaUserSessionAttributeMapper.CROSS_DEVICE_LOA,
                                "http://eidas.europa.eu/LoA/substantial")),
                context);

        assertThat(sessionNote(context, "acr")).isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(sessionNote(context, "eidas_loa")).isNull();
    }

    @Test
    void blankConfiguredValuesFallBackToTheDefaults() {
        BrokeredIdentityContext context = contextWithFlow(Oid4vpConstants.FLOW_SAME_DEVICE);

        mapper.importNewUser(
                null,
                null,
                null,
                model(Map.of(
                        OID4VPEidasLoaUserSessionAttributeMapper.ATTRIBUTE, " ",
                        OID4VPEidasLoaUserSessionAttributeMapper.SAME_DEVICE_LOA, "")),
                context);

        assertThat(sessionNote(context, "eidas_loa")).isEqualTo("STORK-QAA-Level-4");
    }

    @Test
    void contextWithoutPresentationFlowSetsNoNote() {
        BrokeredIdentityContext context = contextWithFlow(null);

        mapper.importNewUser(null, null, null, model(Map.of()), context);

        assertThat(sessionNote(context, "eidas_loa")).isNull();
    }

    // The note is per login state, so it must also be set on the preprocess path, which runs for
    // existing users whose effective sync mode skips updateBrokeredUser.
    @Test
    void preprocessAndUpdatePathsAlsoSetTheNote() {
        BrokeredIdentityContext preprocessed = contextWithFlow(Oid4vpConstants.FLOW_SAME_DEVICE);
        BrokeredIdentityContext updated = contextWithFlow(Oid4vpConstants.FLOW_CROSS_DEVICE);

        mapper.preprocessFederatedIdentity(null, null, model(Map.of()), preprocessed);
        mapper.updateBrokeredUser(null, null, null, model(Map.of()), updated);

        assertThat(sessionNote(preprocessed, "eidas_loa")).isEqualTo("STORK-QAA-Level-4");
        assertThat(sessionNote(updated, "eidas_loa")).isEqualTo("STORK-QAA-Level-3");
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

    private static IdentityProviderMapperModel model(Map<String, String> config) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        model.setConfig(new HashMap<>(config));
        return model;
    }

    // Without an authentication session the context stores session notes in its context data.
    @SuppressWarnings("unchecked")
    private static String sessionNote(BrokeredIdentityContext context, String name) {
        Map<String, String> notes =
                (Map<String, String>) context.getContextData().get(Constants.MAPPER_SESSION_NOTES);
        return notes == null ? null : notes.get(name);
    }

    private static BrokeredIdentityContext contextWithFlow(String flow) {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("test-user", config);
        if (flow != null) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY, flow);
        }
        return context;
    }
}
