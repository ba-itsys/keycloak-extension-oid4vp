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

import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The claims a DCQL query requests for one credential entry, used to validate that a wallet
 * presentation contains everything the verifier asked for.
 *
 * <p>{@code claimPaths} are mapper-style paths ({@code address/street_address} for nested SD-JWT
 * claims, {@code namespace/element} for mDoc claims), matching the key conventions of verified
 * claim maps. {@code claimSets} holds the DCQL {@code claim_sets} options as path lists in
 * preference order; an empty list means every claim in {@code claimPaths} is required.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">OID4VP 1.0 §6.4 — Claims Query</a>
 */
public record RequestedCredential(String format, String type, List<String> claimPaths, List<List<String>> claimSets) {

    public RequestedCredential {
        claimPaths = claimPaths != null ? List.copyOf(claimPaths) : List.of();
        claimSets = claimSets != null ? claimSets.stream().map(List::copyOf).toList() : List.of();
    }

    /** Derives the requested claims model for a credential type aggregated from IdP mappers. */
    public static RequestedCredential of(CredentialTypeSpec spec) {
        List<String> paths = spec.claimSpecs().stream().map(ClaimSpec::path).toList();
        List<List<String>> claimSets = spec.claimSetOptionIndexes().stream()
                .map(option -> option.stream().map(paths::get).toList())
                .toList();
        return new RequestedCredential(spec.format(), spec.type(), paths, claimSets);
    }

    /** Whether this requested credential entry matches a verified credential's format and type. */
    public boolean matches(VerifiedCredential credential) {
        String credentialFormat = credential.presentationType() == PresentationType.MDOC
                ? Oid4vpConstants.FORMAT_MSO_MDOC
                : Oid4vpConstants.FORMAT_SD_JWT_VC;
        return format.equals(credentialFormat) && type.equals(credential.credentialType());
    }

    /**
     * Returns the requested claims the presented claims do not satisfy. Without claim sets, every
     * claim path is required. With claim sets, the presentation must satisfy at least one option;
     * when none is satisfied, the missing claims of the most-preferred option are returned.
     */
    public List<String> missingClaims(Map<String, Object> presentedClaims) {
        if (claimSets.isEmpty()) {
            return missingFrom(claimPaths, presentedClaims);
        }
        List<String> preferredOptionMissing = null;
        for (List<String> option : claimSets) {
            List<String> missing = missingFrom(option, presentedClaims);
            if (missing.isEmpty()) {
                return List.of();
            }
            if (preferredOptionMissing == null) {
                preferredOptionMissing = missing;
            }
        }
        return preferredOptionMissing;
    }

    private static List<String> missingFrom(List<String> paths, Map<String, Object> presentedClaims) {
        List<String> missing = new ArrayList<>();
        for (String path : paths) {
            if (Oid4vpMapperUtils.getNestedValue(presentedClaims, path) == null) {
                missing.add(path);
            }
        }
        return missing;
    }
}
