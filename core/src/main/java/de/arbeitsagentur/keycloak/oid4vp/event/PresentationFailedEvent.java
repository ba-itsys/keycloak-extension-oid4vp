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

/**
 * Reports a wallet response that ended without a verified presentation. Filter on {@link Origin},
 * because a wallet that reports an error can be a user who declined.
 */
public record PresentationFailedEvent(
        String realmId,
        String identityProvider,
        String clientId,
        String state,
        String flow,
        Origin origin,
        String error,
        String reason)
        implements Oid4vpEvent {

    public enum Origin {
        VERIFIER,
        SERVER,
        WALLET,
        TRANSPORT
    }

    @Override
    public String eventType() {
        return Oid4vpEventDetails.EventTypes.PRESENTATION_FAILED;
    }

    @Override
    public Map<String, String> details() {
        return Oid4vpEventDetails.of(
                Oid4vpEventDetails.IDENTITY_PROVIDER,
                identityProvider,
                Oid4vpEventDetails.STATE,
                state,
                Oid4vpEventDetails.FLOW,
                flow,
                Oid4vpEventDetails.ORIGIN,
                origin,
                Oid4vpEventDetails.ERROR,
                error,
                Oid4vpEventDetails.REASON,
                reason);
    }
}
