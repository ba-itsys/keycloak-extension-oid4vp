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

import static de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperConfigProperties.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperConfigProperties;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.ArrayList;
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
import org.keycloak.utils.StringUtil;

public class Oid4vpClaimToUserAttributeMapper extends AbstractIdentityProviderMapper {

    private static final Logger LOG = Logger.getLogger(Oid4vpClaimToUserAttributeMapper.class);

    public static final String PROVIDER_ID = "oid4vp-user-attribute-mapper";

    public static final String USER_ATTRIBUTE = "user.attribute";

    private static final String[] COMPATIBLE_PROVIDERS = new String[] {Oid4vpConstants.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        Oid4vpMapperConfigProperties.addCommonProperties(CONFIG_PROPERTIES);

        ProviderConfigProperty attributeProperty = new ProviderConfigProperty();
        attributeProperty.setName(USER_ATTRIBUTE);
        attributeProperty.setLabel("User Attribute Name");
        attributeProperty.setHelpText(
                "Keycloak user attribute. Use 'email', 'firstName', 'lastName', 'username' for standard properties, or any name for custom attributes.");
        attributeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(attributeProperty);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Claim to User Attribute";
    }

    @Override
    public String getHelpText() {
        return "Map a claim from the verifiable credential to a Keycloak user attribute.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        if (!Oid4vpMapperUtils.matchesCredential(mapperModel, context)) {
            return;
        }

        String claimPath = mapperModel.getConfig().get(CLAIM_PATH);
        String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (StringUtil.isBlank(claimPath) || StringUtil.isBlank(userAttribute)) {
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (!isOptional) {
                LOG.warnf("Required claim '%s' not found in credential", claimPath);
            }
            return;
        }

        applyToContext(context, userAttribute, claimValue);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        if (!Oid4vpMapperUtils.matchesCredential(mapperModel, context)) {
            return;
        }

        String claimPath = mapperModel.getConfig().get(CLAIM_PATH);
        String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (StringUtil.isBlank(claimPath) || StringUtil.isBlank(userAttribute)) {
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (!isOptional) {
                LOG.warnf("Required claim '%s' not found during user update", claimPath);
            }
            return;
        }

        applyToUser(user, userAttribute, claimValue);
    }

    private void applyToContext(BrokeredIdentityContext context, String attribute, Object claimValue) {
        String stringValue = Oid4vpMapperUtils.toStringValue(claimValue);
        if (stringValue == null) return;

        switch (attribute.toLowerCase()) {
            case "email" -> context.setEmail(stringValue);
            case "firstname", "first_name", "givenname", "given_name" -> context.setFirstName(stringValue);
            case "lastname", "last_name", "familyname", "family_name" -> context.setLastName(stringValue);
            case "username" -> context.setUsername(stringValue);
            default -> context.setUserAttribute(attribute, Oid4vpMapperUtils.toStringList(claimValue));
        }
    }

    private void applyToUser(UserModel user, String attribute, Object claimValue) {
        String stringValue = Oid4vpMapperUtils.toStringValue(claimValue);
        if (stringValue == null) return;

        switch (attribute.toLowerCase()) {
            case "email" -> user.setEmail(stringValue);
            case "firstname", "first_name", "givenname", "given_name" -> user.setFirstName(stringValue);
            case "lastname", "last_name", "familyname", "family_name" -> user.setLastName(stringValue);
            case "username" -> user.setUsername(stringValue);
            default -> user.setAttribute(attribute, Oid4vpMapperUtils.toStringList(claimValue));
        }
    }
}
