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

import static org.assertj.core.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderModel;

class Oid4vpMapperUtilsTest {

    @Test
    void getNestedValue_directKey_returnsValue() {
        Map<String, Object> claims = Map.of("given_name", "Alice");

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "given_name")).isEqualTo("Alice");
    }

    @Test
    void getNestedValue_nestedPath_navigatesCorrectly() {
        Map<String, Object> claims = Map.of("address", Map.of("street", "Main St", "city", "Berlin"));

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "address/street")).isEqualTo("Main St");
        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "address/city")).isEqualTo("Berlin");
    }

    @Test
    void getNestedValue_mdocFlatKey_prefersExactMatch() {
        // mDoc uses flat keys like "eu.europa.ec.eudi.pid.1/family_name"
        Map<String, Object> claims = new HashMap<>();
        claims.put("eu.europa.ec.eudi.pid.1/family_name", "Smith");
        claims.put("eu.europa.ec.eudi.pid.1", Map.of("family_name", "Jones"));

        // Exact key match should take priority over nested navigation
        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "eu.europa.ec.eudi.pid.1/family_name"))
                .isEqualTo("Smith");
    }

    @Test
    void getNestedValue_missingKey_returnsNull() {
        Map<String, Object> claims = Map.of("given_name", "Alice");

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "missing")).isNull();
    }

    @Test
    void getNestedValue_missingNestedKey_returnsNull() {
        Map<String, Object> claims = Map.of("address", Map.of("street", "Main St"));

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "address/zip")).isNull();
    }

    @Test
    void getNestedValue_nullClaims_returnsNull() {
        assertThat(Oid4vpMapperUtils.getNestedValue(null, "key")).isNull();
    }

    @Test
    void getNestedValue_nullPath_returnsNull() {
        assertThat(Oid4vpMapperUtils.getNestedValue(Map.of("key", "val"), null)).isNull();
    }

    @Test
    void getNestedValue_deeplyNested_navigatesMultipleLevels() {
        Map<String, Object> claims = Map.of("a", Map.of("b", Map.of("c", "deep")));

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "a/b/c")).isEqualTo("deep");
    }

    @Test
    void getNestedValue_nonMapIntermediate_returnsNull() {
        Map<String, Object> claims = Map.of("a", "not-a-map");

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "a/b")).isNull();
    }

    @Test
    void getNestedValue_suffixMatch_findsMdocNamespacedClaim() {
        // When claim path is just "family_name", it should match "eu.europa.ec.eudi.pid.1/family_name"
        Map<String, Object> claims = Map.of(
                "eu.europa.ec.eudi.pid.1/family_name", "Smith",
                "eu.europa.ec.eudi.pid.1/given_name", "Alice");

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "family_name")).isEqualTo("Smith");
        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "given_name")).isEqualTo("Alice");
    }

    @Test
    void getNestedValue_exactMatchTakesPriorityOverSuffixMatch() {
        // If there's both an exact match and a suffix match, exact wins
        Map<String, Object> claims = new HashMap<>();
        claims.put("family_name", "Direct");
        claims.put("eu.europa.ec.eudi.pid.1/family_name", "Namespaced");

        assertThat(Oid4vpMapperUtils.getNestedValue(claims, "family_name")).isEqualTo("Direct");
    }

    @Test
    void getClaimValue_extractsFromContext() {
        IdentityProviderModel idpModel = new IdentityProviderModel();
        idpModel.setAlias("test-idp");
        BrokeredIdentityContext context = new BrokeredIdentityContext("id", idpModel);
        context.getContextData().put("oid4vp_claims", Map.of("sub", "user123"));

        assertThat(Oid4vpMapperUtils.getClaimValue(context, "sub")).isEqualTo("user123");
    }

    @Test
    void getClaimValue_noClaims_returnsNull() {
        IdentityProviderModel idpModel = new IdentityProviderModel();
        idpModel.setAlias("test-idp");
        BrokeredIdentityContext context = new BrokeredIdentityContext("id", idpModel);

        assertThat(Oid4vpMapperUtils.getClaimValue(context, "sub")).isNull();
    }
}
