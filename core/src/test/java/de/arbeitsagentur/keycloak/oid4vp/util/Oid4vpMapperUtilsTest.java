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
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
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

        JsonNode claims = Oid4vpMapperUtils.toClaimsNode(credential);

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

        JsonNode claims = Oid4vpMapperUtils.toClaimsNode(credential);

        assertThat(claims.path("org.iso.18013.5.1").path("given_name").asText()).isEqualTo("Erika");
        assertThat(claims.path("org.iso.18013.5.1").path("family_name").asText())
                .isEqualTo("Mustermann");
        assertThat(claims.path("status").asText()).isEqualTo("valid");
    }

    @Test
    void claimsNode_returnsStoredNode() throws Exception {
        BrokeredIdentityContext context = context();
        JsonNode claims = JsonSerialization.readValue("{\"email\":\"a@example.org\"}", JsonNode.class);
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, claims);

        assertThat(Oid4vpMapperUtils.claimsNode(context)).isSameAs(claims);
    }

    @Test
    void claimsNode_coercesSerializedMapBackIntoTree() {
        // A context round-tripped through the authentication session restores the tree as maps.
        BrokeredIdentityContext context = context();
        context.getContextData()
                .put(Oid4vpMapperUtils.CONTEXT_CLAIMS_KEY, Map.of("address", Map.of("locality", "Berlin")));

        JsonNode claims = Oid4vpMapperUtils.claimsNode(context);

        assertThat(claims.path("address").path("locality").asText()).isEqualTo("Berlin");
    }

    @Test
    void claimsNode_missingClaims_returnsNull() {
        assertThat(Oid4vpMapperUtils.claimsNode(context())).isNull();
    }

    private static BrokeredIdentityContext context() {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        return new BrokeredIdentityContext("test-user", config);
    }
}
