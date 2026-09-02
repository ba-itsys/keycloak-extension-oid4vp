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
 * The claims a DCQL query requests for one credential entry, kept so that a presentation can be
 * validated against everything the verifier asked for. The presented credential has to be of one
 * of the accepted {@code types}, and its claims are addressed as a {@link ClaimPath}, scoped to a
 * namespace for mDoc.
 *
 * <p>{@code claimSets} holds the DCQL {@code claim_sets} options as index lists into
 * {@code claims}, in preference order. An empty list means every claim is required.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public record RequestedCredential(
        String id, String format, List<String> types, List<RequestedClaim> claims, List<List<Integer>> claimSets)
        implements PresentationRequirements {

    /** One requested claim, where the namespace is the mDoc namespace and null for SD-JWT. */
    public record RequestedClaim(String namespace, String path) {

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
        types = types != null ? List.copyOf(types) : List.of();
        claims = claims != null ? List.copyOf(claims) : List.of();
        claimSets = claimSets != null ? claimSets.stream().map(List::copyOf).toList() : List.of();
    }

    public RequestedCredential(
            String id, String format, String type, List<RequestedClaim> claims, List<List<Integer>> claimSets) {
        this(id, format, List.of(type), claims, claimSets);
    }

    /**
     * Builds the requirements of an aggregated credential entry from its expanded claims, so that
     * the claim set indexes match the generated query.
     */
    public static RequestedCredential of(String credentialId, CredentialTypeSpec spec) {
        List<RequestedClaim> claims = spec.requestedClaims().stream()
                .map(claimSpec -> new RequestedClaim(claimSpec.namespace(), claimSpec.path()))
                .toList();
        return new RequestedCredential(credentialId, spec.format(), spec.types(), claims, spec.claimSetOptionIndexes());
    }

    /** Returns whether the credential has this format and one of the accepted types, directly or by derivation. */
    public boolean matches(VerifiedCredential credential) {
        return format.equals(credential.presentationType().dcqlFormat())
                && types.stream().anyMatch(credential::isOfType);
    }

    public String describeTypes() {
        return String.join(", ", types);
    }

    @Override
    public void checkIfSatisfiedBy(JsonNode disclosedPayload) throws VerificationException {
        List<String> missing = missingClaims(disclosedPayload);
        if (!missing.isEmpty()) {
            throw new VerificationException("Presentation for credential type '" + describeTypes()
                    + "' does not contain all requested claims. Missing: " + String.join(", ", missing));
        }
    }

    /**
     * Returns the requested claims the presentation does not satisfy. Without claim sets every
     * claim is required, otherwise the presentation has to satisfy at least one option, and when
     * none is satisfied the result names the missing claims of the most preferred option.
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
