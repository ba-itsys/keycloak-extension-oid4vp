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
import java.util.Map;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.util.JsonSerialization;

/**
 * Captures the fully disclosed payload produced by Keycloak's SD-JWT verifier so the verified
 * claims, issuer and VCT can be read after verification.
 */
public class Oid4vpPresentationRequirements implements PresentationRequirements {

    private JsonNode disclosedPayload;

    @Override
    public void checkIfSatisfiedBy(JsonNode disclosedPayload) throws VerificationException {
        this.disclosedPayload = disclosedPayload != null ? disclosedPayload.deepCopy() : null;

        if (disclosedPayload == null || disclosedPayload.isNull()) {
            throw new VerificationException("No disclosed SD-JWT payload available");
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
