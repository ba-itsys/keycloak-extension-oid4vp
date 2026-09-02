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

/** The Keycloak verifier configuration matching one conformance plan variant. */
public record VerifierScenario(CredentialProfile profile, String clientIdScheme, String responseMode) {

    public static VerifierScenario fromVariant(String planName, Map<String, String> planVariant) {
        // The vp_profile plan variant wins when present. The HAIP plan does not expose it, because
        // the plan itself pins the haip profile, so there the plan name decides.
        String vpProfile = planVariant.getOrDefault("vp_profile", planName.contains("haip") ? "haip" : "plain_vp");
        boolean haip = "haip".equals(vpProfile);
        CredentialProfile profile = "iso_mdl".equals(planVariant.get("credential_format"))
                ? CredentialProfile.ISO_MDL
                : CredentialProfile.SD_JWT_VC;
        String clientIdScheme = haip ? "x509_hash" : planVariant.get("client_id_prefix");
        // The haip profile pins the encrypted response mode, while the plain profile falls back to
        // the unencrypted one when the variant leaves it open.
        String responseMode = planVariant.getOrDefault("response_mode", haip ? "direct_post.jwt" : "direct_post");
        return new VerifierScenario(profile, clientIdScheme, haip ? "direct_post.jwt" : responseMode);
    }
}
