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
package de.arbeitsagentur.keycloak.oid4vp.it.conformance;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import java.util.Map;

/** Models the OIDF verifier test-plan variant selection for one OID4VP conformance run. */
record OidfConformanceVariant(
        OidfConformanceCredentialFormat credentialFormat,
        Oid4vpClientIdScheme clientIdScheme,
        OidfConformanceRequestMethod requestMethod,
        Oid4vpResponseMode responseMode) {

    Map<String, String> toQueryParameters() {
        return Map.of(
                "credential_format",
                credentialFormat.parameterValue(),
                "client_id_prefix",
                clientIdScheme.configValue(),
                "request_method",
                requestMethod.parameterValue(),
                "response_mode",
                responseMode.parameterValue());
    }

    enum OidfConformanceCredentialFormat {
        SD_JWT_VC("sd_jwt_vc"),
        ISO_MDL("iso_mdl");

        private final String parameterValue;

        OidfConformanceCredentialFormat(String parameterValue) {
            this.parameterValue = parameterValue;
        }

        String parameterValue() {
            return parameterValue;
        }
    }

    enum OidfConformanceRequestMethod {
        REQUEST_URI_SIGNED("request_uri_signed");

        private final String parameterValue;

        OidfConformanceRequestMethod(String parameterValue) {
            this.parameterValue = parameterValue;
        }

        String parameterValue() {
            return parameterValue;
        }
    }
}
