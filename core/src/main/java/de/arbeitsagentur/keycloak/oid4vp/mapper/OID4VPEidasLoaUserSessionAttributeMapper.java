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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpPresentationFlow;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Writes an eIDAS level of assurance into a user session attribute, choosing the value by whether
 * the presentation finished in the same-device or the cross-device flow.
 */
public class OID4VPEidasLoaUserSessionAttributeMapper extends AbstractIdentityProviderMapper {

    private static final Logger logger = Logger.getLogger(OID4VPEidasLoaUserSessionAttributeMapper.class);

    public static final String PROVIDER_ID = "oid4vp-eidas-loa-user-session-attribute-idp-mapper";

    public static final String ATTRIBUTE = "attribute";
    public static final String SAME_DEVICE_LOA = "loa.same-device";
    public static final String CROSS_DEVICE_LOA = "loa.cross-device";

    public static final String DEFAULT_ATTRIBUTE = "eidas_loa";
    public static final String DEFAULT_SAME_DEVICE_LOA = "STORK-QAA-Level-4";
    public static final String DEFAULT_CROSS_DEVICE_LOA = "STORK-QAA-Level-3";

    private static final String[] COMPATIBLE_PROVIDERS = {Oid4vpConstants.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(ATTRIBUTE)
            .label("User Session Attribute")
            .helpText("Name of the user session attribute to store the level of assurance in.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(DEFAULT_ATTRIBUTE)
            .add()
            .property()
            .name(SAME_DEVICE_LOA)
            .label("Same-Device Level of Assurance")
            .helpText("Value stored when the presentation finished in the same-device flow.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(DEFAULT_SAME_DEVICE_LOA)
            .add()
            .property()
            .name(CROSS_DEVICE_LOA)
            .label("Cross-Device Level of Assurance")
            .helpText("Value stored when the presentation finished in the cross-device flow.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(DEFAULT_CROSS_DEVICE_LOA)
            .add()
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayCategory() {
        return "User Session";
    }

    @Override
    public String getDisplayType() {
        return "eIDAS LoA User Session Attribute";
    }

    @Override
    public String getHelpText() {
        return "Store a level of assurance in the specified user session attribute, chosen by whether the "
                + "presentation finished in the same-device or the cross-device flow. Use together with the "
                + "'User Session Note' protocol mapper on your client or client scope to make the level "
                + "available in tokens. Set the mapper's sync mode override to 'Force' so the attribute is "
                + "also set when a first wallet login links an existing account.";
    }

    /**
     * The note is per login state, so preprocessing sets it too because it runs for every login,
     * while the user centric hooks below never run for an existing user whose effective sync mode
     * is IMPORT.
     */
    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        addSessionNote(mapperModel, context);
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        addSessionNote(mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        addSessionNote(mapperModel, context);
    }

    private void addSessionNote(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        Oid4vpPresentationFlow flow = Oid4vpMapperUtils.presentationFlow(context);
        if (flow == null) {
            logger.warnf("No presentation flow in the brokered context, mapper %s sets nothing", mapperModel.getName());
            return;
        }
        String value =
                switch (flow) {
                    case SAME_DEVICE -> configOrDefault(mapperModel, SAME_DEVICE_LOA, DEFAULT_SAME_DEVICE_LOA);
                    case CROSS_DEVICE -> configOrDefault(mapperModel, CROSS_DEVICE_LOA, DEFAULT_CROSS_DEVICE_LOA);
                };
        context.setSessionNote(configOrDefault(mapperModel, ATTRIBUTE, DEFAULT_ATTRIBUTE), value);
    }

    private static String configOrDefault(IdentityProviderMapperModel mapperModel, String key, String defaultValue) {
        String value = mapperModel.getConfig().get(key);
        return StringUtil.isNotBlank(value) ? value.trim() : defaultValue;
    }
}
