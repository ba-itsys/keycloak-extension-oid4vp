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

/**
 * Imports a data element of the presented mDoc credential into a user session attribute. The
 * claim path addresses the element within the configured ISO 18013-5 namespace. Follows the
 * design of the SD-JWT mappers of upstream Keycloak's OID4VP work, which does not cover mDoc yet.
 */
public class OID4VPMdocUserSessionAttributeMapper extends OID4VPSdJwtUserSessionAttributeMapper {

    public static final String PROVIDER_ID = "oid4vp-mdoc-user-session-attribute-idp-mapper";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property(credentialTypeProperty("Doctype of the mDoc credential this data element is requested from."))
            .property(OID4VPMdocUserAttributeMapper.namespaceProperty())
            .property(claimProperty())
            .property()
            .name(ATTRIBUTE)
            .label("User Session Attribute")
            .helpText("Name of the user session attribute to store the claim in.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property(credentialIdProperty())
            .property(claimSetIdsProperty())
            .build();

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
        return "mDoc User Session Attribute Importer";
    }

    @Override
    public String getHelpText() {
        return "Import the configured data element of the presented mDoc credential into the specified user "
                + "session attribute. Use together with the 'User Session Note' protocol mapper on your client or "
                + "client scope to make the claim available in tokens.";
    }

    @Override
    public String credentialFormat() {
        return Oid4vpConstants.FORMAT_MSO_MDOC;
    }

    @Override
    protected boolean claimSourceConfigured(IdentityProviderMapperModel mapperModel) {
        return OID4VPMdocUserAttributeMapper.namespaceConfigured(mapperModel);
    }

    @Override
    protected JsonNode claimsRoot(IdentityProviderMapperModel mapperModel, PresentedCredential credential) {
        return credential.claimsNode().get(OID4VPMdocUserAttributeMapper.namespace(mapperModel));
    }
}
