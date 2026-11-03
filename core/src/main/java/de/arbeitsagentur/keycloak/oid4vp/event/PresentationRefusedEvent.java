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

import java.util.Map;

public record PresentationRefusedEvent(
        String realmId,
        String identityProvider,
        String clientId,
        String userId,
        String state,
        Refusal refusal,
        String reason)
        implements Oid4vpEvent {

    public enum Refusal {
        USER_MISMATCH,
        LEVEL_NOT_OFFERED,
        CREDENTIAL_IGNORED
    }

    @Override
    public String eventType() {
        return Oid4vpEventDetails.EventTypes.PRESENTATION_REFUSED;
    }

    @Override
    public Map<String, String> details() {
        return Oid4vpEventDetails.of(
                Oid4vpEventDetails.IDENTITY_PROVIDER,
                identityProvider,
                Oid4vpEventDetails.STATE,
                state,
                Oid4vpEventDetails.REFUSAL,
                refusal,
                Oid4vpEventDetails.REASON,
                reason);
    }
}
