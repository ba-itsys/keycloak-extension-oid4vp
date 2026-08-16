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
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;

/**
 * Covers value conversion and target application, mirroring the test cases of upstream Keycloak's
 * {@code OID4VPSdJwtUserAttributeMapperTest}. Claim path semantics are covered by
 * {@link ClaimPathTest}; credential matching is covered here because this extension supports
 * several credentials per request.
 */
class OID4VPSdJwtUserAttributeMapperTest {

    private final OID4VPSdJwtUserAttributeMapper mapper = new OID4VPSdJwtUserAttributeMapper();

    @Test
    void mapsStringClaimToSingleValuedAttribute() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");

        preprocess(context, "email", "emailAttribute");

        assertThat(context.getUserAttribute("emailAttribute")).isEqualTo("alice@email.cz");
    }

    @Test
    void mapsNumberAndBooleanClaimsAsText() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"age": 42, "adult": true}""");

        preprocess(context, "age", "age");
        preprocess(context, "adult", "adult");

        assertThat(context.getUserAttribute("age")).isEqualTo("42");
        assertThat(context.getUserAttribute("adult")).isEqualTo("true");
    }

    @Test
    void mapsArrayOfStringsToMultivaluedAttribute() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"degrees": ["BSc", "MSc"]}""");

        preprocess(context, "degrees", "degrees");

        assertThat(attributeValues(context, "degrees")).containsExactly("BSc", "MSc");
    }

    @Test
    void mapsArrayOfObjectsToJsonElements() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"nationalities": [{"country": "DE"}, {"country": "CZ"}]}""");

        preprocess(context, "nationalities", "nationalities");

        assertThat(attributeValues(context, "nationalities"))
                .containsExactly("{\"country\":\"DE\"}", "{\"country\":\"CZ\"}");
    }

    @Test
    void mapsFannedOutMatchesToMultivaluedAttribute() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"degrees": [{"type": "BSc"}, {"type": "MSc"}]}""");

        preprocess(context, "degrees[].type", "degreeTypes");

        assertThat(attributeValues(context, "degreeTypes")).containsExactly("BSc", "MSc");
    }

    @Test
    void mapsObjectClaimToJsonAttribute() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"address": {"street_address": "221B Baker Street", "locality": "London"}}""");

        preprocess(context, "address", "addressJson");

        assertThat(context.getUserAttribute("addressJson"))
                .as("keys are ordered, so the attribute does not change when a wallet renders the claim differently")
                .isEqualTo("{\"locality\":\"London\",\"street_address\":\"221B Baker Street\"}");
    }

    @Test
    void missingClaimSetsNoAttribute() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");

        preprocess(context, "phone", "phone");

        assertThat(context.getUserAttribute("phone")).isNull();
    }

    @Test
    void invalidClaimPathMapsNothing() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"degrees": ["BSc"]}""");

        preprocess(context, "degrees[x]", "notAnIndex");

        assertThat(context.getUserAttribute("notAnIndex")).isNull();
    }

    @Test
    void mapsSpecialTargetsToUserProperties() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"sub": "alice", "email": "alice@email.cz", "given_name": "Alice", "family_name": "Wonder"}""");

        preprocess(context, "sub", "username");
        preprocess(context, "email", "email");
        preprocess(context, "given_name", "firstName");
        preprocess(context, "family_name", "lastName");

        assertThat(context.getModelUsername()).isEqualTo("alice");
        assertThat(context.getEmail()).isEqualTo("alice@email.cz");
        assertThat(context.getFirstName()).isEqualTo("Alice");
        assertThat(context.getLastName()).isEqualTo("Wonder");
    }

    @Test
    void blankConfigurationMapsNothing() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");

        preprocess(context, "", "emailAttribute");
        preprocess(context, "email", "");

        assertThat(context.getUserAttribute("emailAttribute")).isNull();
        assertThat(context.getEmail()).isNull();
    }

    @Test
    void mismatchedCredentialTypeMapsNothing() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");

        mapper.preprocessFederatedIdentity(
                null, null, model("email", "emailAttribute", "urn:other:credential"), context);

        assertThat(context.getUserAttribute("emailAttribute")).isNull();
    }

    @Test
    void mdocPresentationMapsNothing() throws Exception {
        BrokeredIdentityContext context = MapperTestContexts.context(PresentationType.MDOC, "urn:eudi:pid:1", """
                {"eu.europa.ec.eudi.pid.1": {"family_name": "Wonder"}}""");

        preprocess(context, "eu\\.europa\\.ec\\.eudi\\.pid\\.1.family_name", "lastName");

        assertThat(context.getLastName()).isNull();
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

    private void preprocess(BrokeredIdentityContext context, String claim, String attribute) {
        mapper.preprocessFederatedIdentity(null, null, model(claim, attribute, "urn:eudi:pid:1"), context);
    }

    private static IdentityProviderMapperModel model(String claim, String attribute, String credentialType) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, claim);
        config.put(OID4VPSdJwtUserAttributeMapper.USER_ATTRIBUTE, attribute);
        config.put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, credentialType);
        model.setConfig(config);
        return model;
    }

    static BrokeredIdentityContext contextWithClaims(String claimsJson) throws Exception {
        return MapperTestContexts.context(PresentationType.SD_JWT, "urn:eudi:pid:1", claimsJson);
    }

    @SuppressWarnings("unchecked")
    private static List<String> attributeValues(BrokeredIdentityContext context, String attribute) {
        return (List<String>) context.getContextData().get("user.attributes." + attribute);
    }
}
