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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.util.JsonSerialization;

/**
 * OID4VP-specific presentation requirements for SD-JWT verification.
 *
 * <p>This class serves two purposes:
 * <ul>
 *   <li>optionally enforce a minimal verifier policy (VCT + required claims)</li>
 *   <li>capture the fully disclosed payload produced by Keycloak's SD-JWT verifier</li>
 * </ul>
 */
public class Oid4vpPresentationRequirements implements PresentationRequirements {

    private final Set<String> expectedCredentialTypes;
    private final Set<String> requiredClaims;
    private JsonNode disclosedPayload;

    public Oid4vpPresentationRequirements() {
        this(List.of(), List.of());
    }

    public Oid4vpPresentationRequirements(List<String> expectedCredentialTypes, List<String> requiredClaims) {
        this.expectedCredentialTypes =
                new LinkedHashSet<>(expectedCredentialTypes != null ? expectedCredentialTypes : List.of());
        this.requiredClaims = new LinkedHashSet<>(requiredClaims != null ? requiredClaims : List.of());
    }

    @Override
    @SuppressWarnings("unchecked")
    public void checkIfSatisfiedBy(JsonNode disclosedPayload) throws VerificationException {
        this.disclosedPayload = disclosedPayload != null ? disclosedPayload.deepCopy() : null;

        if (disclosedPayload == null || disclosedPayload.isNull()) {
            throw new VerificationException("No disclosed SD-JWT payload available");
        }

        if (!expectedCredentialTypes.isEmpty()) {
            String vct = readStringClaim(disclosedPayload, "vct");
            if (vct == null || !expectedCredentialTypes.contains(vct)) {
                throw new VerificationException("Unexpected `vct` claim value: " + vct);
            }
        }

        for (String requiredClaim : requiredClaims) {
            JsonNode claim = disclosedPayload.get(requiredClaim);
            if (claim == null || claim.isNull()) {
                throw new VerificationException("A required field was not presented: `" + requiredClaim + "`");
            }
        }
    }

    public SdJwtVerificationResult getVerifiedResult() {
        if (disclosedPayload == null) {
            throw new IllegalStateException("No disclosed SD-JWT payload captured");
        }
        Map<String, Object> claims = JsonSerialization.mapper.convertValue(disclosedPayload, Map.class);
        return new SdJwtVerificationResult(
                claims, readStringClaim(disclosedPayload, "iss"), readStringClaim(disclosedPayload, "vct"));
    }

    private String readStringClaim(JsonNode payload, String name) {
        JsonNode claim = payload.get(name);
        return claim != null && claim.isTextual() ? claim.textValue() : null;
    }
}
