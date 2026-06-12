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
package de.arbeitsagentur.keycloak.oid4vp.conformance.verifier;

import java.util.Map;

/**
 * The Keycloak verifier configuration matching one conformance plan variant. Derived from the
 * plan name and its variant selection.
 */
public record VerifierScenario(
        CredentialProfile profile, String clientIdScheme, String responseMode, boolean enforceHaip) {

    public static VerifierScenario fromVariant(String planName, Map<String, String> planVariant) {
        // The vp_profile plan variant is authoritative when present. The HAIP plan does not expose
        // it as a variant because the plan itself pins the haip profile, so fall back to the plan name.
        String vpProfile = planVariant.getOrDefault("vp_profile", planName.contains("haip") ? "haip" : "plain_vp");
        boolean haip = "haip".equals(vpProfile);
        CredentialProfile profile = "iso_mdl".equals(planVariant.get("credential_format"))
                ? CredentialProfile.ISO_MDL
                : CredentialProfile.SD_JWT_VC;
        String clientIdScheme = haip ? "x509_hash" : planVariant.get("client_id_prefix");
        String responseMode = planVariant.get("response_mode");
        return new VerifierScenario(profile, clientIdScheme, responseMode, haip);
    }
}
