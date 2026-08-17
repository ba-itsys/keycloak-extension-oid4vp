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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimPath;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;

/**
 * The claims a DCQL query requests for one credential entry, used to validate that a presentation
 * contains everything the verifier asked for. Claims are addressed like in the mappers: a
 * {@link ClaimPath}, for mDoc claims scoped to a namespace. {@code claimSets} holds the DCQL
 * {@code claim_sets} options as index lists into {@code claims} in preference order; an empty
 * list means every claim is required.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public record RequestedCredential(
        String id, String format, String type, List<RequestedClaim> claims, List<List<Integer>> claimSets)
        implements PresentationRequirements {

    /** One requested claim: the mDoc namespace (null for SD-JWT) and the claim path. */
    public record RequestedClaim(String namespace, String path) {

        /** Whether the presented claims contain this claim. */
        public boolean presentIn(JsonNode presentedClaims) {
            JsonNode root = namespace == null
                    ? presentedClaims
                    : presentedClaims != null ? presentedClaims.get(namespace) : null;
            ClaimPath claimPath = ClaimPath.parse(path);
            return claimPath != null && !claimPath.select(root).isEmpty();
        }

        public String describe() {
            return namespace == null ? path : namespace + ":" + path;
        }
    }

    public RequestedCredential {
        claims = claims != null ? List.copyOf(claims) : List.of();
        claimSets = claimSets != null ? claimSets.stream().map(List::copyOf).toList() : List.of();
    }

    /** Derives the requested claims model for a credential type aggregated from IdP mappers. */
    public static RequestedCredential of(String credentialId, CredentialTypeSpec spec) {
        List<RequestedClaim> claims = spec.claimSpecs().stream()
                .map(claimSpec -> new RequestedClaim(claimSpec.namespace(), claimSpec.path()))
                .toList();
        return new RequestedCredential(credentialId, spec.format(), spec.type(), claims, spec.claimSetOptionIndexes());
    }

    /** Whether this requested credential entry matches a verified credential's format and type. */
    public boolean matches(VerifiedCredential credential) {
        String credentialFormat = credential.presentationType() == PresentationType.MDOC
                ? Oid4vpConstants.FORMAT_MSO_MDOC
                : Oid4vpConstants.FORMAT_SD_JWT_VC;
        return format.equals(credentialFormat) && type.equals(credential.credentialType());
    }

    /** Rejects presentations that do not contain the requested claims. */
    @Override
    public void checkIfSatisfiedBy(JsonNode disclosedPayload) throws VerificationException {
        List<String> missing = missingClaims(disclosedPayload);
        if (!missing.isEmpty()) {
            throw new VerificationException("Presentation for credential type '" + type
                    + "' does not contain all requested claims. Missing: " + String.join(", ", missing));
        }
    }

    /**
     * Returns the requested claims the presented claims do not satisfy. Without claim sets, every
     * claim is required. With claim sets, the presentation must satisfy at least one option; when
     * none is satisfied, the missing claims of the most-preferred option are returned.
     */
    public List<String> missingClaims(JsonNode presentedClaims) {
        if (claimSets.isEmpty()) {
            return missingFrom(claims, presentedClaims);
        }
        List<String> preferredOptionMissing = null;
        for (List<Integer> option : claimSets) {
            List<String> missing = missingFrom(option.stream().map(claims::get).toList(), presentedClaims);
            if (missing.isEmpty()) {
                return List.of();
            }
            if (preferredOptionMissing == null) {
                preferredOptionMissing = missing;
            }
        }
        return preferredOptionMissing;
    }

    private static List<String> missingFrom(List<RequestedClaim> requested, JsonNode presentedClaims) {
        List<String> missing = new ArrayList<>();
        for (RequestedClaim claim : requested) {
            if (!claim.presentIn(presentedClaims)) {
                missing.add(claim.describe());
            }
        }
        return missing;
    }
}
