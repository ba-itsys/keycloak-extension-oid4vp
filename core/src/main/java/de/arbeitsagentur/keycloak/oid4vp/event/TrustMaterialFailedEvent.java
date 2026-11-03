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
 * Reports trust material that is missing or weaker than configured. {@code reference} names the
 * trust list or the provider aliases.
 */
public record TrustMaterialFailedEvent(
        String realmId,
        String trustProviderId,
        Failure failure,
        String reference,
        boolean staleDataInUse,
        String reason)
        implements Oid4vpEvent {

    public enum Failure {
        REFRESH_FAILED,
        UNSIGNED,
        UNAVAILABLE
    }

    @Override
    public String eventType() {
        return Oid4vpEventDetails.EventTypes.TRUST_MATERIAL_FAILED;
    }

    @Override
    public Map<String, String> details() {
        return Oid4vpEventDetails.of(
                Oid4vpEventDetails.TRUST_PROVIDER,
                trustProviderId,
                Oid4vpEventDetails.FAILURE,
                failure,
                Oid4vpEventDetails.REFERENCE,
                reference,
                Oid4vpEventDetails.STALE_DATA_IN_USE,
                staleDataInUse,
                Oid4vpEventDetails.REASON,
                reason);
    }
}
