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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.util.JsonSerialization;

/**
 * The test configuration uploaded to the conformance suite when creating a verifier plan. The
 * structure is defined by the suite: the verifier's client identifier and the trust anchor used to
 * validate the request object chain, plus the verifier's signing key.
 */
public record VerifierSuiteConfig(
        String alias, String description, String publish, Client client, Credential credential) {

    public static VerifierSuiteConfig create(
            String alias, String clientId, String requestObjectTrustAnchorPem, JsonNode signingJwk) {
        return new VerifierSuiteConfig(
                alias,
                "Keycloak OID4VP verifier conformance",
                "private",
                new Client(clientId, requestObjectTrustAnchorPem),
                new Credential(signingJwk));
    }

    public JsonNode toJson() {
        return JsonSerialization.writeValueAsNode(this);
    }

    public record Client(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("request_object_trust_anchor_pem") String requestObjectTrustAnchorPem) {}

    public record Credential(@JsonProperty("signing_jwk") JsonNode signingJwk) {}
}
