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

import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Specification of a credential type to request, used when building DCQL queries from IdP mappers.
 *
 * @param format the credential format ({@code dc+sd-jwt} or {@code mso_mdoc})
 * @param type the credential type identifier (VCT for SD-JWT, doctype for mDoc)
 * @param claimSpecs the claims to request within this credential
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6 — DCQL Query</a>
 */
public record CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {

    /**
     * Computes the DCQL {@code claim_sets} options as indexes into {@link #claimSpecs()}. One
     * option is generated per distinct claim set id, ordered lexicographically by id; claims
     * without ids are members of every option. An empty result means no {@code claim_sets} entry
     * is generated and all claims are required.
     */
    public List<List<Integer>> claimSetOptionIndexes() {
        SortedSet<String> claimSetIds = new TreeSet<>();
        for (ClaimSpec claimSpec : claimSpecs) {
            claimSetIds.addAll(claimSpec.claimSetIds());
        }
        if (claimSetIds.isEmpty()) {
            return List.of();
        }
        List<List<Integer>> options = new ArrayList<>();
        for (String claimSetId : claimSetIds) {
            List<Integer> option = new ArrayList<>();
            for (int i = 0; i < claimSpecs.size(); i++) {
                List<String> memberIds = claimSpecs.get(i).claimSetIds();
                if (memberIds.isEmpty() || memberIds.contains(claimSetId)) {
                    option.add(i);
                }
            }
            options.add(option);
        }
        return options;
    }
}
