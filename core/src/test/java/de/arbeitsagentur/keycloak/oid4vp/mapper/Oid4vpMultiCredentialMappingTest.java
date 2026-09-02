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

import static org.assertj.core.api.Assertions.*;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;

/**
 * Claim extraction is scoped to the credential a mapper is configured for. Credentials of one
 * presentation routinely carry the same claim names. A mapper that resolved its claim path over
 * the claims of all presented credentials would import a value from the wrong credential.
 */
class Oid4vpMultiCredentialMappingTest {

    private static final String PID_ID = "sdjwt_urn_eudi_pid_1";
    private static final String MDL_ID = "mdoc_org_iso_18013_5_1_mDL";
    private static final String PID_VCT = "urn:eudi:pid:1";
    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";

    private final OID4VPSdJwtUserAttributeMapper sdJwtMapper = new OID4VPSdJwtUserAttributeMapper();
    private final OID4VPMdocUserAttributeMapper mdocMapper = new OID4VPMdocUserAttributeMapper();

    @Test
    void collidingClaimNameResolvesWithinTheSdJwtCredential() {
        BrokeredIdentityContext context = twoCredentialContext();

        sdJwtMapper.preprocessFederatedIdentity(null, null, sdJwtModel("family_name", "pidFamilyName"), context);

        assertThat(context.getUserAttribute("pidFamilyName"))
                .as("the SD-JWT mapper must read the family_name of its own credential")
                .isEqualTo("Mustermann");
    }

    @Test
    void collidingClaimNameResolvesWithinTheMdocCredential() {
        BrokeredIdentityContext context = twoCredentialContext();

        mdocMapper.preprocessFederatedIdentity(null, null, mdocModel("family_name", "mdlFamilyName"), context);

        assertThat(context.getUserAttribute("mdlFamilyName"))
                .as("the mDoc mapper must read the family_name of its own credential")
                .isEqualTo("Musterfrau");
    }

    @Test
    void mappersOfEveryPresentedCredentialRun() {
        BrokeredIdentityContext context = twoCredentialContext();

        sdJwtMapper.preprocessFederatedIdentity(null, null, sdJwtModel("family_name", "pidFamilyName"), context);
        mdocMapper.preprocessFederatedIdentity(null, null, mdocModel("family_name", "mdlFamilyName"), context);

        assertThat(context.getUserAttribute("pidFamilyName")).isEqualTo("Mustermann");
        assertThat(context.getUserAttribute("mdlFamilyName"))
                .as("a mapper of a credential that is not the first presented one must still run")
                .isEqualTo("Musterfrau");
    }

    @Test
    void explicitCredentialIdSelectsBetweenTwoEntriesOfTheSameCredentialType() {
        Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put(
                "pid_full",
                sdJwtCredential("pid_full", PID_VCT, Map.of("family_name", "Mustermann", "given_name", "Erika")));
        credentials.put("pid_minimal", sdJwtCredential("pid_minimal", PID_VCT, Map.of("family_name", "Musterfrau")));

        BrokeredIdentityContext context = contextOf(credentials);
        IdentityProviderMapperModel model = sdJwtModel("family_name", "minimalFamilyName");
        model.getConfig().put(AbstractOID4VPClaimMapper.CREDENTIAL_ID, "pid_minimal");

        sdJwtMapper.preprocessFederatedIdentity(null, null, model, context);

        assertThat(context.getUserAttribute("minimalFamilyName"))
                .as("the credential id disambiguates two entries of the same credential type")
                .isEqualTo("Musterfrau");
    }

    @Test
    void mapperOfACredentialThatWasNotPresentedMapsNothing() {
        Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put(PID_ID, sdJwtCredential(PID_ID, PID_VCT, Map.of("family_name", "Mustermann")));

        BrokeredIdentityContext context = contextOf(credentials);

        mdocMapper.preprocessFederatedIdentity(null, null, mdocModel("family_name", "mdlFamilyName"), context);

        assertThat(context.getUserAttribute("mdlFamilyName")).isNull();
    }

    private BrokeredIdentityContext twoCredentialContext() {
        Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put(PID_ID, sdJwtCredential(PID_ID, PID_VCT, Map.of("family_name", "Mustermann")));
        credentials.put(
                MDL_ID,
                mdocCredential(MDL_ID, MDL_DOCTYPE, Map.of(MDL_NAMESPACE, Map.of("family_name", "Musterfrau"))));
        return contextOf(credentials);
    }

    private static BrokeredIdentityContext contextOf(Map<String, VerifiedCredential> credentials) {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("test-user", config);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY, PresentedCredentials.of(credentials));
        return context;
    }

    private static VerifiedCredential sdJwtCredential(String credentialId, String vct, Map<String, Object> claims) {
        return new VerifiedCredential(credentialId, "https://issuer.example", vct, claims, PresentationType.SD_JWT);
    }

    private static VerifiedCredential mdocCredential(String credentialId, String doctype, Map<String, Object> claims) {
        return new VerifiedCredential(credentialId, null, doctype, claims, PresentationType.MDOC);
    }

    private static IdentityProviderMapperModel sdJwtModel(String claim, String attribute) {
        return model(claim, attribute, PID_VCT, null);
    }

    private static IdentityProviderMapperModel mdocModel(String claim, String attribute) {
        return model(claim, attribute, MDL_DOCTYPE, MDL_NAMESPACE);
    }

    private static IdentityProviderMapperModel model(
            String claim, String attribute, String credentialType, String namespace) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, claim);
        config.put(OID4VPSdJwtUserAttributeMapper.USER_ATTRIBUTE, attribute);
        config.put(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE, credentialType);
        if (namespace != null) {
            config.put(OID4VPMdocUserAttributeMapper.NAMESPACE, namespace);
        }
        model.setConfig(config);
        return model;
    }
}
