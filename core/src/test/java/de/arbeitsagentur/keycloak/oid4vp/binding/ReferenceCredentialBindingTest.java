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

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;

/**
 * The values that decide whether a credential this Keycloak issued belongs to the presentation it
 * is shown in. Both sides of that decision run in different logins, so what matters is that the same
 * presentation always yields the same digest and a different one never does.
 */
class ReferenceCredentialBindingTest {

    private static final String PID = "pid";
    private static final String EMPLOYEE = "employee";
    private static final String PID_VCT = "urn:eudi:pid:1";

    private static final SecretKey CURRENT = secret("current-realm-hmac-key");
    private static final SecretKey ROTATED_IN = secret("rotated-in-realm-hmac-key");
    private static final SecretKey FOREIGN = secret("some-other-realms-hmac-key");

    private final ReferenceCredentialBinding realm = binding(CURRENT, List.of(CURRENT));

    @Test
    void theSamePresentationAlwaysProducesTheSameBinding() {
        String issued = realm.referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);

        assertThat(realm.matches(presentation("Erika", "Mustermann"), EMPLOYEE, issued))
                .as("the user presents the credential again, next to the same PID")
                .isTrue();
    }

    @Test
    void aPresentationOfSomebodyElsesCredentialsDoesNotMatch() {
        String issued = realm.referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);

        assertThat(realm.matches(presentation("Max", "Mustermann"), EMPLOYEE, issued))
                .as("the credential was issued for another person's PID, so it identifies nobody here")
                .isFalse();
    }

    @Test
    void theOrderTheWalletAnsweredInDoesNotChangeTheBinding() {
        PresentedCredentials pidFirst = new PresentedCredentials(ordered(PID, EMPLOYEE));
        PresentedCredentials employeeFirst = new PresentedCredentials(ordered(EMPLOYEE, PID));

        assertThat(realm.referenceBindingOf(employeeFirst, EMPLOYEE))
                .as("a wallet may answer the credentials in any order")
                .isEqualTo(realm.referenceBindingOf(pidFirst, EMPLOYEE));
    }

    @Test
    void aRotatedKeyStillAcceptsWhatTheOldOneIssued() {
        String issuedBeforeTheRotation = binding(ROTATED_IN, List.of(ROTATED_IN))
                .referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);
        ReferenceCredentialBinding afterRotation = binding(CURRENT, List.of(CURRENT, ROTATED_IN));

        assertThat(afterRotation.matches(presentation("Erika", "Mustermann"), EMPLOYEE, issuedBeforeTheRotation))
                .as("a key rotation must not lock out every credential that is already in a wallet")
                .isTrue();
        assertThat(afterRotation.referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE))
                .as("new credentials are bound with the active key")
                .isNotEqualTo(issuedBeforeTheRotation);
    }

    @Test
    void aBindingOfAnotherRealmDoesNotMatch() {
        String issuedElsewhere =
                binding(FOREIGN, List.of(FOREIGN)).referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);

        assertThat(realm.matches(presentation("Erika", "Mustermann"), EMPLOYEE, issuedElsewhere))
                .as("the digest is keyed, so it means nothing outside the realm that computed it")
                .isFalse();
    }

    @Test
    void theBindingHidesTheClaimsItIsTakenOver() {
        String issued = realm.referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);

        assertThat(issued)
                .as("the value rides in a credential shown to other verifiers")
                .doesNotContain("Erika")
                .doesNotContain("Mustermann");
    }

    @Test
    void aCredentialWithoutABindingIsAcceptedAnywhere() {
        assertThat(realm.matches(presentation("Erika", "Mustermann"), EMPLOYEE, null))
                .as("credentials of other issuers carry no binding and are not this check's business")
                .isTrue();
        assertThat(realm.matches(presentation("Erika", "Mustermann"), EMPLOYEE, "  "))
                .isTrue();
    }

    @Test
    void aPresentationBindingToNothingRefusesABoundCredential() {
        String issued = realm.referenceBindingOf(presentation("Erika", "Mustermann"), EMPLOYEE);
        PresentedCredentials employeeAlone = new PresentedCredentials(
                Map.of(EMPLOYEE, new PresentedCredential("dc+sd-jwt", "https://kc.example/badge", Map.of())));

        assertThat(realm.matches(employeeAlone, EMPLOYEE, issued))
                .as("the credential says it was issued alongside a PID, and none is here")
                .isFalse();
    }

    @Test
    void aSubjectIsStableForTheUserAndSaysNothingAboutThem() {
        String subject = realm.subjectOf("1f2b0c9e-1111-4a2b-9c3d-5e6f70819aaa");

        assertThat(subject).isEqualTo(realm.subjectOf("1f2b0c9e-1111-4a2b-9c3d-5e6f70819aaa"));
        assertThat(subject)
                .as("the wallet and every verifier the credential reaches would otherwise read the user id")
                .doesNotContain("1f2b0c9e");
        assertThat(subject).isNotEqualTo(realm.subjectOf("another-user-id"));
    }

    @Test
    void aSubjectOfAnotherRealmIsAnotherSubject() {
        assertThat(realm.subjectOf("user-1"))
                .isNotEqualTo(binding(FOREIGN, List.of(FOREIGN)).subjectOf("user-1"));
    }

    @Test
    void aSubjectIsNotTheBindingOfTheSameInput() {
        // Both are HMACs of the same realm secret, so they are separated by their context string.
        assertThat(realm.subjectOf("value"))
                .isNotEqualTo(realm.referenceBindingOf(presentation("value", "value"), null));
    }

    @Test
    void aDisabledRealmKeyStopsVerifyingBindings() {
        KeyWrapper enabled = hmacKeyWrapper(CURRENT, KeyStatus.ACTIVE);
        KeyWrapper passive = hmacKeyWrapper(ROTATED_IN, KeyStatus.PASSIVE);
        KeyWrapper disabled = hmacKeyWrapper(FOREIGN, KeyStatus.DISABLED);

        assertThat(ReferenceCredentialBinding.acceptedSecrets(Stream.of(enabled, passive, disabled)))
                .as("disabling a compromised key must invalidate every binding it computed")
                .containsExactly(CURRENT, ROTATED_IN);
    }

    private static KeyWrapper hmacKeyWrapper(SecretKey secret, KeyStatus status) {
        KeyWrapper key = new KeyWrapper();
        key.setSecretKey(secret);
        key.setUse(KeyUse.SIG);
        key.setStatus(status);
        return key;
    }

    private static ReferenceCredentialBinding binding(SecretKey active, List<SecretKey> accepted) {
        return new ReferenceCredentialBinding(
                new FixedRealmSecrets(active, accepted),
                new PidReferenceBindingProvider(
                        Set.of(PID_VCT),
                        PidReferenceBindingProviderFactory.parseClaims(
                                PidReferenceBindingProviderFactory.DEFAULT_CLAIMS)));
    }

    private static PresentedCredentials presentation(String givenName, String familyName) {
        Map<String, Object> pidClaims = new LinkedHashMap<>();
        pidClaims.put("given_name", givenName);
        pidClaims.put("family_name", familyName);
        pidClaims.put("birthdate", "1964-08-12");
        Map<String, PresentedCredential> credentials = new LinkedHashMap<>();
        credentials.put(PID, new PresentedCredential("dc+sd-jwt", PID_VCT, pidClaims));
        credentials.put(EMPLOYEE, new PresentedCredential("dc+sd-jwt", "https://kc.example/badge", Map.of()));
        return new PresentedCredentials(credentials);
    }

    /** The same two credentials, in the given answer order. */
    private static Map<String, PresentedCredential> ordered(String first, String second) {
        Map<String, PresentedCredential> all =
                presentation("Erika", "Mustermann").byCredentialId();
        Map<String, PresentedCredential> reordered = new LinkedHashMap<>();
        reordered.put(first, all.get(first));
        reordered.put(second, all.get(second));
        return reordered;
    }

    private static SecretKey secret(String material) {
        return new SecretKeySpec(material.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    /** The realm secrets, as a typed double of what the session provides. */
    private record FixedRealmSecrets(SecretKey active, List<SecretKey> allAccepted)
            implements ReferenceCredentialBinding.RealmSecrets {}
}
