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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import java.util.List;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Maps a data element of the presented mDoc credential to a user property or attribute. The claim
 * path addresses the element within the configured ISO 18013-5 namespace; deeper path steps
 * address into structured element values. Follows the design of the SD-JWT mappers of upstream
 * Keycloak's OID4VP work, which does not cover mDoc yet.
 */
public class OID4VPMdocUserAttributeMapper extends OID4VPSdJwtUserAttributeMapper {

    public static final String PROVIDER_ID = "oid4vp-mdoc-user-attribute-idp-mapper";

    public static final String NAMESPACE = "namespace";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property(credentialTypeProperty("Doctype of the mDoc credential this data element is requested from."))
            .property(namespaceProperty())
            .property(claimProperty())
            .property()
            .name(USER_ATTRIBUTE)
            .label("User Attribute Name")
            .helpText("User attribute name to store the claim. Use username, email, firstName and lastName "
                    + "to map to those predefined user properties.")
            .type(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE)
            .add()
            .property(credentialIdProperty())
            .property(claimSetIdsProperty())
            .build();

    static ProviderConfigProperty namespaceProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(NAMESPACE);
        property.setLabel("Namespace");
        property.setHelpText("ISO 18013-5 namespace of the data element, i.e. 'org.iso.18013.5.1'. "
                + "Defaults to the credential type (doctype) when left empty.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        return property;
    }

    /** The effective namespace: the configured one, falling back to the doctype. */
    static String namespace(IdentityProviderMapperModel mapperModel) {
        String namespace = mapperModel.getConfig().get(NAMESPACE);
        if (StringUtil.isNotBlank(namespace)) {
            return namespace.trim();
        }
        String doctype = mapperModel.getConfig().get(CREDENTIAL_TYPE);
        return StringUtil.isNotBlank(doctype) ? doctype.trim() : null;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayType() {
        return "mDoc Attribute Importer";
    }

    @Override
    public String getHelpText() {
        return "Import the configured data element of the presented mDoc credential into the specified user "
                + "property or attribute. String, number and boolean elements are imported as a single value, "
                + "arrays as a multivalued attribute, and structured values as their JSON representation.";
    }

    @Override
    public String credentialFormat() {
        return Oid4vpConstants.FORMAT_MSO_MDOC;
    }

    @Override
    protected JsonNode claimsRoot(IdentityProviderMapperModel mapperModel, PresentedCredential credential) {
        String namespace = namespace(mapperModel);
        if (namespace == null) {
            logger.warnf("No namespace or credential type configured for mapper %s", mapperModel.getName());
            return null;
        }
        return credential.claimsNode().get(namespace);
    }
}
