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
package de.arbeitsagentur.keycloak.oid4vp.binding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PidReferenceBindingProviderTest {

    private static final String PID = "pid";
    private static final String MDOC_PID = "mdoc_pid";
    private static final String EMPLOYEE = "employee";
    private static final String PID_VCT = "urn:eudi:pid:1";
    private static final String PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
    private static final String EMPLOYEE_VCT = "https://kc.example/employee";

    private static final PidReferenceBindingProvider DEFAULTS = new PidReferenceBindingProvider(
            Set.copyOf(PidReferenceBindingProviderFactory.parse(
                    PidReferenceBindingProviderFactory.DEFAULT_CREDENTIAL_TYPES)),
            PidReferenceBindingProviderFactory.parseClaims(PidReferenceBindingProviderFactory.DEFAULT_CLAIMS));

    @Test
    void bindsToTheIdentifyingClaimsOfThePidByDefault() {
        Map<String, BoundCredential> material = DEFAULTS.bindingMaterial(presentation(), EMPLOYEE);

        assertThat(material).containsOnlyKeys(PID);
        assertThat(material.get(PID).claims())
                .as("the mandatory PID attributes identify the holder and change rarely")
                .containsOnly(
                        Map.entry("given_name", "Erika"),
                        Map.entry("family_name", "Mustermann"),
                        Map.entry("birthdate", "1964-08-12"));
    }

    @Test
    void bindsToTheCredentialTypeTheClaimsWereReadFrom() {
        // The same name and date of birth out of another credential is another statement, so a
        // credential of a type this deployment does not mean must not produce the same binding.
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1964-08-12");
        PidReferenceBindingProvider anyType = new PidReferenceBindingProvider(
                Set.of(),
                PidReferenceBindingProviderFactory.parseClaims(PidReferenceBindingProviderFactory.DEFAULT_CLAIMS));

        BoundCredential fromPid = anyType.bindingMaterial(
                        new PresentedCredentials(Map.of(PID, new PresentedCredential("dc+sd-jwt", PID_VCT, claims))),
                        EMPLOYEE)
                .get(PID);
        BoundCredential fromLoyaltyCard = anyType.bindingMaterial(
                        new PresentedCredentials(
                                Map.of(PID, new PresentedCredential("dc+sd-jwt", "https://shop.example/card", claims))),
                        EMPLOYEE)
                .get(PID);

        assertThat(fromPid.claims()).isEqualTo(fromLoyaltyCard.claims());
        assertThat(fromPid).isNotEqualTo(fromLoyaltyCard);
    }

    @Test
    void findsTheSameClaimsInsideAnMdocNamespace() {
        Map<String, Object> namespace = new LinkedHashMap<>();
        namespace.put("given_name", "Erika");
        namespace.put("family_name", "Mustermann");
        namespace.put("birthdate", "1964-08-12");
        Map<String, PresentedCredential> credentials =
                Map.of(MDOC_PID, new PresentedCredential("mso_mdoc", PID_DOCTYPE, Map.of(PID_DOCTYPE, namespace)));

        Map<String, BoundCredential> material =
                DEFAULTS.bindingMaterial(new PresentedCredentials(credentials), EMPLOYEE);

        assertThat(material.get(MDOC_PID).claims())
                .as("an mDoc keeps its data elements inside a namespace, and the path is tried in each one")
                .containsOnlyKeys("given_name", "family_name", "birthdate");
    }

    @Test
    void addressesNestedClaimsOfAnSdJwtCredentialByPath() {
        PidReferenceBindingProvider provider =
                new PidReferenceBindingProvider(Set.of(PID_VCT), List.of("place_of_birth.locality"));

        assertThat(provider.bindingMaterial(presentation(), EMPLOYEE).get(PID).claims())
                .as("SD-JWT claims nest, so the path addresses the claim rather than its name alone")
                .containsExactly(Map.entry("place_of_birth.locality", "Köln"));
    }

    @Test
    void bindsToAnObjectClaimWithItsKeysOrdered() {
        PidReferenceBindingProvider provider =
                new PidReferenceBindingProvider(Set.of(PID_VCT), List.of("place_of_birth"));

        assertThat(provider.bindingMaterial(presentation(), EMPLOYEE).get(PID).claims())
                .as("the digest has to be the same whatever order the wallet rendered the claim in")
                .containsExactly(Map.entry("place_of_birth", "{\"country\":\"DE\",\"locality\":\"Köln\"}"));
    }

    @Test
    void selectedClaimsAreOrderedWhateverOrderTheyWereConfiguredIn() {
        PidReferenceBindingProvider asConfigured =
                new PidReferenceBindingProvider(Set.of(PID_VCT), List.of("given_name", "birthdate"));
        PidReferenceBindingProvider reversed =
                new PidReferenceBindingProvider(Set.of(PID_VCT), List.of("birthdate", "given_name"));

        assertThat(asConfigured.bindingMaterial(presentation(), EMPLOYEE))
                .as("the digest is taken over this, so the configured order must not reach it")
                .isEqualTo(reversed.bindingMaterial(presentation(), EMPLOYEE));
    }

    @Test
    void ignoresCredentialsOfAnotherType() {
        assertThat(DEFAULTS.bindingMaterial(presentation(), null))
                .as("only the credentials naming the person are bound to, whatever else was presented")
                .containsOnlyKeys(PID);
    }

    @Test
    void neverBindsTheCredentialToItself() {
        PidReferenceBindingProvider everyCredential = new PidReferenceBindingProvider(Set.of(), List.of("given_name"));

        assertThat(everyCredential.bindingMaterial(presentation(), EMPLOYEE)).doesNotContainKey(EMPLOYEE);
    }

    @Test
    void bindsToNothingWhenTheSelectedClaimsWereNotPresented() {
        PidReferenceBindingProvider provider =
                new PidReferenceBindingProvider(Set.of(PID_VCT), List.of("personal_administrative_number"));

        assertThat(provider.bindingMaterial(presentation(), EMPLOYEE)).isEmpty();
    }

    @Test
    void bindingToEveryClaimIsRefusedBecauseItWouldCoverTheIssuanceMetadata() {
        assertThatThrownBy(() -> PidReferenceBindingProviderFactory.parseClaims("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(PidReferenceBindingProviderFactory.CLAIMS);
    }

    private static PresentedCredentials presentation() {
        Map<String, PresentedCredential> credentials = new LinkedHashMap<>();
        Map<String, Object> placeOfBirth = new LinkedHashMap<>();
        placeOfBirth.put("locality", "Köln");
        placeOfBirth.put("country", "DE");
        Map<String, Object> pidClaims = new LinkedHashMap<>();
        pidClaims.put("given_name", "Erika");
        pidClaims.put("family_name", "Mustermann");
        pidClaims.put("birthdate", "1964-08-12");
        pidClaims.put("place_of_birth", placeOfBirth);
        pidClaims.put("iss", "https://pid.example");
        credentials.put(PID, new PresentedCredential("dc+sd-jwt", PID_VCT, pidClaims));
        credentials.put(EMPLOYEE, new PresentedCredential("dc+sd-jwt", EMPLOYEE_VCT, Map.of("sub", "s")));
        return new PresentedCredentials(credentials);
    }
}
