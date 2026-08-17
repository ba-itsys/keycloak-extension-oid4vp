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

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;

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

    // Without a namespace or doctype the mapper is misconfigured, so an update must leave the
    // existing attribute untouched instead of removing it.
    @Test
    void updateKeepsAttributeWhenNamespaceIsUnconfigured() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"given_name": "Erika"}}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("givenName", List.of("Keep"));

        mapper.updateBrokeredUser(null, null, user, model("given_name", "givenName", null, null), context);

        assertThat(user.getAttributeStream("givenName")).containsExactly("Keep");
    }

    // A well-configured mapper whose namespace the credential does not carry keeps the
    // remove-on-absent update semantics.
    @Test
    void updateRemovesAttributeWhenNamespaceIsAbsentFromTheCredential() throws Exception {
        BrokeredIdentityContext context = mdlContext("""
                {"org.iso.18013.5.1": {"given_name": "Erika"}}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("givenName", List.of("Stale"));

        mapper.updateBrokeredUser(
                null, null, user, model("given_name", "givenName", "org.iso.other", MDL_DOCTYPE), context);

        assertThat(user.getAttributeStream("givenName")).isEmpty();
    }

    @Test
    void sdJwtPresentationMapsNothing() throws Exception {
        BrokeredIdentityContext context = MapperTestContexts.context(PresentationType.SD_JWT, MDL_DOCTYPE, """
                {"org.iso.18013.5.1": {"given_name": "Erika"}}""");

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
        return MapperTestContexts.context(PresentationType.MDOC, doctype, claimsJson);
    }
}
