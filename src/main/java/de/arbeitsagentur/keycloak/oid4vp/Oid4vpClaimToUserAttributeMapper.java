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
package de.arbeitsagentur.keycloak.oid4vp;

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

    public static final String CREDENTIAL_FORMAT = "credential.format";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CLAIM_PATH = "claim";
    public static final String USER_ATTRIBUTE = "user.attribute";
    public static final String OPTIONAL = "optional";

    private static final String[] COMPATIBLE_PROVIDERS = new String[] {Oid4vpIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty formatProperty = new ProviderConfigProperty();
        formatProperty.setName(CREDENTIAL_FORMAT);
        formatProperty.setLabel("Credential Format");
        formatProperty.setHelpText("Format of the credential containing this claim.");
        formatProperty.setType(ProviderConfigProperty.LIST_TYPE);
        formatProperty.setDefaultValue(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC);
        formatProperty.setOptions(
                List.of(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC, Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC));
        CONFIG_PROPERTIES.add(formatProperty);

        ProviderConfigProperty typeProperty = new ProviderConfigProperty();
        typeProperty.setName(CREDENTIAL_TYPE);
        typeProperty.setLabel("Credential Type");
        typeProperty.setHelpText("Credential type identifier. For SD-JWT: vct value. For mDoc: docType value.");
        typeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(typeProperty);

        ProviderConfigProperty claimProperty = new ProviderConfigProperty();
        claimProperty.setName(CLAIM_PATH);
        claimProperty.setLabel("Claim Path");
        claimProperty.setHelpText(
                "Path to the claim in the credential. Use '/' for nested paths (e.g., 'given_name', 'eu.europa.ec.eudi.pid.1/family_name').");
        claimProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(claimProperty);

        ProviderConfigProperty attributeProperty = new ProviderConfigProperty();
        attributeProperty.setName(USER_ATTRIBUTE);
        attributeProperty.setLabel("User Attribute Name");
        attributeProperty.setHelpText(
                "Keycloak user attribute. Use 'email', 'firstName', 'lastName', 'username' for standard properties, or any name for custom attributes.");
        attributeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(attributeProperty);

        ProviderConfigProperty optionalProperty = new ProviderConfigProperty();
        optionalProperty.setName(OPTIONAL);
        optionalProperty.setLabel("Optional Claim");
        optionalProperty.setHelpText("If enabled, this claim is optional and triggers claim_set generation in DCQL.");
        optionalProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        optionalProperty.setDefaultValue("false");
        CONFIG_PROPERTIES.add(optionalProperty);
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

        String stringValue = claimValue.toString();
        applyToContext(context, userAttribute, stringValue);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
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

        String stringValue = claimValue.toString();
        applyToUser(user, userAttribute, stringValue);
    }

    private void applyToContext(BrokeredIdentityContext context, String attribute, String value) {
        switch (attribute.toLowerCase()) {
            case "email" -> context.setEmail(value);
            case "firstname", "first_name", "givenname", "given_name" -> context.setFirstName(value);
            case "lastname", "last_name", "familyname", "family_name" -> context.setLastName(value);
            case "username" -> context.setUsername(value);
            default -> context.setUserAttribute(attribute, value);
        }
    }

    private void applyToUser(UserModel user, String attribute, String value) {
        switch (attribute.toLowerCase()) {
            case "email" -> user.setEmail(value);
            case "firstname", "first_name", "givenname", "given_name" -> user.setFirstName(value);
            case "lastname", "last_name", "familyname", "family_name" -> user.setLastName(value);
            case "username" -> user.setUsername(value);
            default -> user.setSingleAttribute(attribute, value);
        }
    }
}
