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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.util.JsonSerialization;

class Oid4vpMapperUtilsTest {

    @Test
    void toClaimsNode_sdJwt_convertsClaimsDirectly() {
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1",
                "https://issuer.example",
                "urn:eudi:pid:1",
                Map.of("given_name", "Erika", "address", Map.of("locality", "Berlin")),
                PresentationType.SD_JWT);

        JsonNode claims = new PresentedCredential(
                        credential.presentationType().dcqlFormat(), credential.credentialType(), credential.claims())
                .claimsNode();

        assertThat(claims.path("given_name").asText()).isEqualTo("Erika");
        assertThat(claims.path("address").path("locality").asText()).isEqualTo("Berlin");
    }

    @Test
    void toClaimsNode_mdoc_keepsNamespaceNesting() {
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1",
                null,
                "org.iso.18013.5.1.mDL",
                Map.of(
                        "org.iso.18013.5.1",
                        Map.of("given_name", "Erika", "family_name", "Mustermann"),
                        "status",
                        "valid"),
                PresentationType.MDOC);

        JsonNode claims = new PresentedCredential(
                        credential.presentationType().dcqlFormat(), credential.credentialType(), credential.claims())
                .claimsNode();

        assertThat(claims.path("org.iso.18013.5.1").path("given_name").asText()).isEqualTo("Erika");
        assertThat(claims.path("org.iso.18013.5.1").path("family_name").asText())
                .isEqualTo("Mustermann");
        assertThat(claims.path("status").asText()).isEqualTo("valid");
    }

    @Test
    void presentedCredentials_areScopedPerCredential() {
        BrokeredIdentityContext context = context();
        Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put(
                "pid",
                new VerifiedCredential(
                        "pid",
                        "https://issuer.example",
                        "urn:eudi:pid:1",
                        Map.of("family_name", "Mustermann"),
                        PresentationType.SD_JWT));
        credentials.put(
                "mdl",
                new VerifiedCredential(
                        "mdl",
                        null,
                        "org.iso.18013.5.1.mDL",
                        Map.of("family_name", "Musterfrau"),
                        PresentationType.MDOC));
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY, PresentedCredentials.of(credentials));

        PresentedCredentials presented = Oid4vpMapperUtils.presentedCredentials(context);

        assertThat(presented.get("pid").claims()).containsEntry("family_name", "Mustermann");
        assertThat(presented.get("mdl").claims()).containsEntry("family_name", "Musterfrau");
        assertThat(presented.get("pid").format()).isEqualTo(Oid4vpConstants.FORMAT_SD_JWT_VC);
        assertThat(presented.firstOfFormat(Oid4vpConstants.FORMAT_MSO_MDOC).type())
                .isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void credentialsSurviveTheAuthenticationSessionRoundTrip() throws Exception {
        VerifiedCredential credential = new VerifiedCredential(
                "pid",
                "https://issuer.example",
                "urn:eudi:pid:1",
                Map.of("address", Map.of("locality", "Berlin")),
                PresentationType.SD_JWT);

        // The authentication session stores the context data as JSON and restores it through the
        // recorded class, so the typed model has to survive the round trip.
        String serialized = JsonSerialization.writeValueAsString(PresentedCredentials.of(Map.of("pid", credential)));
        PresentedCredentials restored = JsonSerialization.readValue(serialized, PresentedCredentials.class);

        BrokeredIdentityContext context = context();
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY, restored);

        PresentedCredentials presented = Oid4vpMapperUtils.presentedCredentials(context);
        assertThat(presented.get("pid").type()).isEqualTo("urn:eudi:pid:1");
        assertThat(presented
                        .get("pid")
                        .claimsNode()
                        .path("address")
                        .path("locality")
                        .asText())
                .isEqualTo("Berlin");
    }

    @Test
    void presentedCredentials_missingContextData_returnsNull() {
        assertThat(Oid4vpMapperUtils.presentedCredentials(context())).isNull();
    }

    private static BrokeredIdentityContext context() {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        return new BrokeredIdentityContext("test-user", config);
    }
}
