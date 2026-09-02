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
    void updateSetsAttributeFromPresentClaim() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");
        InMemoryUser user = new InMemoryUser();

        update(user, context, "email", "emailAttribute");

        assertThat(user.getAttributeStream("emailAttribute")).containsExactly("alice@email.cz");
    }

    @Test
    void updateRemovesAttributeWhenClaimIsAbsent() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("phone", List.of("123456"));

        update(user, context, "phone", "phone");

        assertThat(user.getAttributeStream("phone")).isEmpty();
    }

    // A configuration mistake must not wipe user state: unlike an absent claim, a blank or
    // unparseable claim path leaves the existing attribute untouched.
    @Test
    void updateKeepsAttributeWhenClaimPathIsBlank() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("emailAttribute", List.of("keep@email.cz"));

        update(user, context, "", "emailAttribute");

        assertThat(user.getAttributeStream("emailAttribute")).containsExactly("keep@email.cz");
    }

    @Test
    void updateKeepsAttributeWhenClaimPathIsInvalid() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"email": "alice@email.cz"}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("emailAttribute", List.of("keep@email.cz"));

        update(user, context, "email[x]", "emailAttribute");

        assertThat(user.getAttributeStream("emailAttribute")).containsExactly("keep@email.cz");
    }

    // --- alternative claims -------------------------------------------------

    @Test
    void alternativeClaimIsReadWhenTheClaimIsAbsent() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_name": "Gabler"}""");

        preprocessWithAlternatives(context, "birth_family_name", "birth_name", "birthName");

        assertThat(context.getUserAttribute("birthName")).isEqualTo("Gabler");
    }

    @Test
    void claimIsPreferredOverItsAlternatives() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_family_name": "Gabler", "birth_name": "Other"}""");

        preprocessWithAlternatives(context, "birth_family_name", "birth_name", "birthName");

        assertThat(context.getUserAttribute("birthName")).isEqualTo("Gabler");
    }

    @Test
    void alternativesAreTriedInTheirOrder() throws Exception {
        BrokeredIdentityContext bothPresent = contextWithClaims("""
                {"birth_name": "First", "maiden_name": "Second"}""");
        BrokeredIdentityContext lastPresent = contextWithClaims("""
                {"maiden_name": "Second"}""");

        preprocessWithAlternatives(bothPresent, "birth_family_name", "birth_name, maiden_name", "birthName");
        preprocessWithAlternatives(lastPresent, "birth_family_name", "birth_name, maiden_name", "birthName");

        assertThat(bothPresent.getUserAttribute("birthName")).isEqualTo("First");
        assertThat(lastPresent.getUserAttribute("birthName")).isEqualTo("Second");
    }

    @Test
    void alternativesResolveNestedPathsAndArrays() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"names": {"birth": ["Gabler", "Meier"]}}""");

        preprocessWithAlternatives(context, "birth_family_name", "names.birth[]", "birthNames");

        assertThat(attributeValues(context, "birthNames")).containsExactly("Gabler", "Meier");
    }

    @Test
    void alternativeWithNullValueIsSkippedLikeAnAbsentClaim() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_name": null, "maiden_name": "Gabler"}""");

        preprocessWithAlternatives(context, "birth_family_name", "birth_name, maiden_name", "birthName");

        assertThat(context.getUserAttribute("birthName")).isEqualTo("Gabler");
    }

    @Test
    void updateSetsAttributeFromAlternativeClaim() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_name": "Gabler"}""");
        InMemoryUser user = new InMemoryUser();

        mapper.updateBrokeredUser(
                null, null, user, modelWithAlternatives("birth_family_name", "birth_name", "birthName"), context);

        assertThat(user.getAttributeStream("birthName")).containsExactly("Gabler");
    }

    @Test
    void updateRemovesAttributeWhenNeitherClaimNorAlternativeIsPresent() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"given_name": "Erika"}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("birthName", List.of("Old"));

        mapper.updateBrokeredUser(
                null, null, user, modelWithAlternatives("birth_family_name", "birth_name", "birthName"), context);

        assertThat(user.getAttributeStream("birthName")).isEmpty();
    }

    // A malformed alternative misconfigures the mapper as a whole, exactly as the DCQL query
    // generation leaves such a mapper out, so user state stays untouched.
    @Test
    void updateKeepsAttributeWhenAnAlternativePathIsInvalid() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_family_name": "Gabler"}""");
        InMemoryUser user = new InMemoryUser();
        user.setAttribute("birthName", List.of("keep"));

        mapper.updateBrokeredUser(
                null, null, user, modelWithAlternatives("birth_family_name", "birth_name[x]", "birthName"), context);

        assertThat(user.getAttributeStream("birthName")).containsExactly("keep");
    }

    @Test
    void blankAlternativesReadTheClaimOnly() throws Exception {
        BrokeredIdentityContext context = contextWithClaims("""
                {"birth_family_name": "Gabler"}""");

        preprocessWithAlternatives(context, "birth_family_name", " , ", "birthName");

        assertThat(context.getUserAttribute("birthName")).isEqualTo("Gabler");
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

    private void update(InMemoryUser user, BrokeredIdentityContext context, String claim, String attribute) {
        mapper.updateBrokeredUser(null, null, user, model(claim, attribute, "urn:eudi:pid:1"), context);
    }

    private void preprocessWithAlternatives(
            BrokeredIdentityContext context, String claim, String alternatives, String attribute) {
        mapper.preprocessFederatedIdentity(null, null, modelWithAlternatives(claim, alternatives, attribute), context);
    }

    private static IdentityProviderMapperModel modelWithAlternatives(
            String claim, String alternatives, String attribute) {
        IdentityProviderMapperModel model = model(claim, attribute, "urn:eudi:pid:1");
        model.getConfig().put(AbstractOID4VPClaimMapper.CLAIM_ALTERNATIVES, alternatives);
        return model;
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
