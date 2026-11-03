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
package de.arbeitsagentur.keycloak.oid4vp.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;

class KeycloakEventMappingTest {

    @Test
    void verifiedPresentationIsASuccessfulIdentityProviderResponse() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new PresentationVerifiedEvent(
                "realm", "wallet", "client", "state", "same_device", List.of("urn:pid", "urn:mdl")));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE);
        assertThat(event.error()).isNull();
        assertThat(event.clientId()).isEqualTo("client");
        assertThat(event.details())
                .containsEntry(Oid4vpEventDetails.EVENT_TYPE, "PRESENTATION_VERIFIED")
                .containsEntry(Oid4vpEventDetails.IDENTITY_PROVIDER, "wallet")
                .containsEntry(Oid4vpEventDetails.CREDENTIAL_TYPES, "urn:pid,urn:mdl");
    }

    @Test
    void failureIsAnIdentityProviderResponseErrorAndNoLoginError() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new PresentationFailedEvent(
                "realm",
                "wallet",
                "client",
                "state",
                "same_device",
                PresentationFailedEvent.Origin.VERIFIER,
                null,
                "bad signature"));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
        assertThat(event.error()).isEqualTo("oid4vp_presentation_failed");
        assertThat(event.details())
                .containsEntry(Oid4vpEventDetails.ORIGIN, "VERIFIER")
                .containsEntry(Oid4vpEventDetails.REASON, "bad signature")
                .doesNotContainKey(Oid4vpEventDetails.ERROR);
    }

    @Test
    void refusalCarriesTheUserAndIsALoginError() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new PresentationRefusedEvent(
                "realm",
                "wallet",
                "client",
                "user",
                null,
                PresentationRefusedEvent.Refusal.USER_MISMATCH,
                "other user"));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_LOGIN_ERROR);
        assertThat(event.userId()).isEqualTo("user");
        assertThat(event.details()).containsEntry(Oid4vpEventDetails.REFUSAL, "USER_MISMATCH");
    }

    @Test
    void ignoredCredentialIsNoLoginError() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new PresentationRefusedEvent(
                "realm",
                "wallet",
                null,
                null,
                null,
                PresentationRefusedEvent.Refusal.CREDENTIAL_IGNORED,
                "Credential pid: issued for another presentation"));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
    }

    @Test
    void revocationCheckFailureNamesTheMechanismAndTheState() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new RevocationCheckFailedEvent(
                "realm", RevocationMechanism.STATUS_LIST, "https://issuer.example/status", "state", "HTTP 503"));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
        assertThat(event.error()).isEqualTo("oid4vp_revocation_check_failed");
        assertThat(event.details())
                .containsEntry(Oid4vpEventDetails.MECHANISM, "STATUS_LIST")
                .containsEntry(Oid4vpEventDetails.REFERENCE, "https://issuer.example/status")
                .containsEntry(Oid4vpEventDetails.STATE, "state");
    }

    @Test
    void valuesAreBounded() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new CompletionRejectedEvent(
                "realm", "wallet", "x".repeat(5000), CompletionRejectedEvent.Rejection.RESPONSE_CODE, "no record"));

        assertThat(event.details().get(Oid4vpEventDetails.STATE)).hasSizeLessThan(1100);
    }

    @Test
    void walletChosenTextStaysOnOneLine() {
        KeycloakEventMapping event = KeycloakEventMapping.of(new PresentationFailedEvent(
                "realm",
                "wallet",
                "client",
                "state",
                "same_device",
                PresentationFailedEvent.Origin.WALLET,
                "denied\nforged=1",
                null));

        assertThat(event.details()).containsEntry(Oid4vpEventDetails.ERROR, "denied forged=1");
    }
}
