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

// Seals the security events of the extension, so the Keycloak event mapping covers every type.
public sealed interface Oid4vpEvent
        permits PresentationVerifiedEvent,
                PresentationFailedEvent,
                PresentationRefusedEvent,
                CompletionRejectedEvent,
                RevocationDetectedEvent,
                RevocationCheckFailedEvent,
                TrustMaterialFailedEvent {

    // Returns one of the values of `Oid4vpEventDetails.EventTypes`.
    String eventType();

    // Returns null when the code that fires the event runs outside a realm.
    String realmId();

    // Returns null until the flow has identified a user, which is the common case.
    default String userId() {
        return null;
    }

    default String clientId() {
        return null;
    }

    // Returns the event data under the keys of `Oid4vpEventDetails`. It holds no credential claims.
    Map<String, String> details();
}
