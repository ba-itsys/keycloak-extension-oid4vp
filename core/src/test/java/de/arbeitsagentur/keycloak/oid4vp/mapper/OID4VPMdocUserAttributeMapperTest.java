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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.util.JsonSerialization;

/**
 * Covers the mDoc specifics on top of the shared claim mapper behavior: elements are addressed
 * within their namespace, and the namespace falls back to the doctype.
 */
class OID4VPMdocUserAttributeMapperTest {

    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";

    private final OID4VPMdocUserAttributeMapper mapper = new OID4VPMdocUserAttributeMapper();
    private final OID4VPMdocUserSessionAttributeMapper sessionMapper = new OID4VPMdocUserSessionAttributeMapper();

    @Test
    void mapsElementOfConfiguredNamespace() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"given_name": "Erika", "family_name": "Mustermann"}}""");

        mapper.preprocessFederatedIdentity(
                null, null, model("given_name", "firstName", MDL_NAMESPACE, MDL_DOCTYPE), context);

        assertThat(context.getFirstName()).isEqualTo("Erika");
    }

    @Test
    void namespaceFallsBackToDoctype() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"eu.europa.ec.eudi.pid.1": {"family_name": "Mustermann"}}""", "eu.europa.ec.eudi.pid.1");

        mapper.preprocessFederatedIdentity(
                null, null, model("family_name", "lastName", null, "eu.europa.ec.eudi.pid.1"), context);

        assertThat(context.getLastName()).isEqualTo("Mustermann");
    }

    @Test
    void selectsIntoStructuredElementValues() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"driving_privileges": [{"vehicle_category_code": "B"}]}}""");

        mapper.preprocessFederatedIdentity(
                null,
                null,
                model("driving_privileges[].vehicle_category_code", "vehicleCategories", MDL_NAMESPACE, MDL_DOCTYPE),
                context);

        assertThat(context.getUserAttribute("vehicleCategories")).isEqualTo("B");
    }

    @Test
    void missingNamespaceMapsNothing() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"given_name": "Erika"}}""");

        mapper.preprocessFederatedIdentity(
                null, null, model("given_name", "firstName", "org.iso.other", MDL_DOCTYPE), context);

        assertThat(context.getFirstName()).isNull();
    }

    @Test
    void sdJwtPresentationMapsNothing() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"given_name": "Erika"}}""");
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_FORMAT_KEY, Oid4vpConstants.FORMAT_SD_JWT_VC);

        mapper.preprocessFederatedIdentity(
                null, null, model("given_name", "firstName", MDL_NAMESPACE, MDL_DOCTYPE), context);

        assertThat(context.getFirstName()).isNull();
    }

    @Test
    void sessionMapperImportsElementAsNote() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"family_name": "Mustermann"}}""");

        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, "family_name");
        config.put(OID4VPSdJwtUserSessionAttributeMapper.ATTRIBUTE, "credentialFamilyName");
        config.put(OID4VPMdocUserAttributeMapper.NAMESPACE, MDL_NAMESPACE);
        config.put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, MDL_DOCTYPE);
        model.setConfig(config);
        sessionMapper.preprocessFederatedIdentity(null, null, model, context);

        @SuppressWarnings("unchecked")
        Map<String, String> notes =
                (Map<String, String>) context.getContextData().get(Constants.MAPPER_SESSION_NOTES);
        assertThat(notes).containsEntry("credentialFamilyName", "Mustermann");
    }

    private static IdentityProviderMapperModel model(String claim, String attribute, String namespace, String doctype) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, claim);
        config.put(OID4VPSdJwtUserAttributeMapper.USER_ATTRIBUTE, attribute);
        config.put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, doctype);
        if (namespace != null) {
            config.put(OID4VPMdocUserAttributeMapper.NAMESPACE, namespace);
        }
        model.setConfig(config);
        return model;
    }

    private static BrokeredIdentityContext mdlContext(String claimsJson) throws Exception {
        return contextWithClaims(claimsJson, MDL_DOCTYPE);
    }

    private static BrokeredIdentityContext contextWithClaims(String claimsJson, String doctype) throws Exception {
        JsonNode claims = JsonSerialization.readValue(claimsJson, JsonNode.class);
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("test-user", config);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_FORMAT_KEY, Oid4vpConstants.FORMAT_MSO_MDOC);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY, doctype);
        return context;
    }
}
