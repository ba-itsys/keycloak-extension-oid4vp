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
 * Reports a status list or CRL that marks a credential or an issuer certificate as revoked or
 * suspended. {@code reference} names the status list entry or the certificate.
 */
public record RevocationDetectedEvent(
        String realmId, String trustProviderId, RevocationMechanism mechanism, String reference, String state)
        implements Oid4vpEvent {

    @Override
    public String eventType() {
        return Oid4vpEventDetails.EventTypes.REVOCATION_DETECTED;
    }

    @Override
    public Map<String, String> details() {
        return Oid4vpEventDetails.of(
                Oid4vpEventDetails.TRUST_PROVIDER,
                trustProviderId,
                Oid4vpEventDetails.MECHANISM,
                mechanism,
                Oid4vpEventDetails.REFERENCE,
                reference,
                Oid4vpEventDetails.STATE,
                state);
    }
}
