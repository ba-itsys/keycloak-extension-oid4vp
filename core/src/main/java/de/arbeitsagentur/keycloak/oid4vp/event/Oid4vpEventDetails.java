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

import de.arbeitsagentur.keycloak.oid4vp.util.FailureDetails;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class Oid4vpEventDetails {

    // Carries the OID4VP event type in the Keycloak event.
    public static final String EVENT_TYPE = "oid4vp_event_type";

    public static final String CREDENTIAL_TYPES = "oid4vp_credential_types";
    public static final String ERROR = "oid4vp_error";
    public static final String FAILURE = "oid4vp_failure";
    public static final String FLOW = "oid4vp_flow";
    public static final String IDENTITY_PROVIDER = "oid4vp_identity_provider";
    public static final String MECHANISM = "oid4vp_mechanism";
    public static final String ORIGIN = "oid4vp_origin";
    public static final String REASON = "oid4vp_reason";
    public static final String REFERENCE = "oid4vp_reference";
    public static final String REFUSAL = "oid4vp_refusal";
    public static final String REJECTION = "oid4vp_rejection";
    public static final String STATE = "oid4vp_state";

    private static final int MAX_VALUE_LENGTH = 1024;

    private Oid4vpEventDetails() {}

    /**
     * Builds a detail map from key and value pairs, leaving out null values. Wallets and issuers
     * choose parts of these values, so each is reduced to one bounded line for logs and SIEM systems.
     */
    static Map<String, String> of(Object... keysAndValues) {
        Map<String, String> details = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            Object value = keysAndValues[i + 1];
            if (value != null) {
                details.put((String) keysAndValues[i], bounded(FailureDetails.singleLine(text(value))));
            }
        }
        return Collections.unmodifiableMap(details);
    }

    private static String bounded(String value) {
        return value.length() > MAX_VALUE_LENGTH ? value.substring(0, MAX_VALUE_LENGTH) + "..." : value;
    }

    private static String text(Object value) {
        return value instanceof List<?> list
                ? list.stream().map(String::valueOf).collect(Collectors.joining(","))
                : value.toString();
    }

    public static final class EventTypes {

        public static final String PRESENTATION_VERIFIED = "PRESENTATION_VERIFIED";
        public static final String PRESENTATION_FAILED = "PRESENTATION_FAILED";
        public static final String PRESENTATION_REFUSED = "PRESENTATION_REFUSED";
        public static final String COMPLETION_REJECTED = "COMPLETION_REJECTED";
        public static final String REVOCATION_DETECTED = "REVOCATION_DETECTED";
        public static final String REVOCATION_CHECK_FAILED = "REVOCATION_CHECK_FAILED";
        public static final String TRUST_MATERIAL_FAILED = "TRUST_MATERIAL_FAILED";

        private EventTypes() {}
    }
}
