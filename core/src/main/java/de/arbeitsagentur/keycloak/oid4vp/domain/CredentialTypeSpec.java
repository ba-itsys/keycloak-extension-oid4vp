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
import java.util.stream.IntStream;

/**
 * One credential entry of the DCQL query. It holds the format, the accepted types and the claims
 * to request. The identity provider mappers are aggregated into it.
 *
 * <p>An SD-JWT entry can accept several types. DCQL sends them as one {@code vct_values} array.
 * The wallet answers with a credential of any of them. That covers types that differ per country
 * or rulebook version, like {@code urn:eudi:pid:1} and {@code urn:eudi:pid:de:1}. An mDoc entry
 * has exactly one doctype. {@code doctype_value} is a single string.
 *
 * @param format the credential format ({@code dc+sd-jwt} or {@code mso_mdoc})
 * @param types the accepted types (VCTs for SD-JWT, the doctype for mDoc), in request order
 * @param claimSpecs the claims to request, one per mapper
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6 — DCQL Query</a>
 */
public record CredentialTypeSpec(String format, List<String> types, List<ClaimSpec> claimSpecs) {

    public CredentialTypeSpec {
        types = List.copyOf(types);
        if (types.isEmpty()) {
            throw new IllegalArgumentException("A credential needs at least one credential type");
        }
        claimSpecs = List.copyOf(claimSpecs);
    }

    public CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {
        this(format, List.of(type), claimSpecs);
    }

    /** Returns the first accepted type. The default credential id is derived from it. */
    public String firstType() {
        return types.get(0);
    }

    public static List<String> parseTypes(String rawTypes) {
        return ConfigList.parse(rawTypes);
    }

    /**
     * Lists every claim the query asks for. Each spec contributes its own path and its
     * alternatives, in spec order. The claim set options index this list.
     */
    public List<ClaimSpec> requestedClaims() {
        return claimSpecs.stream()
                .flatMap(claimSpec -> claimSpec.expand().stream())
                .toList();
    }

    /**
     * Computes the DCQL {@code claim_sets} options as indexes into {@link #requestedClaims()}. An
     * empty result means the query carries no {@code claim_sets} entry, so every claim is required.
     *
     * <p>The claim set ids give the base options, one per id and sorted by id, with a claim that
     * carries no ids in every option. Alternative paths then multiply each base option by the path
     * choices of its members, so that every option asks for exactly one path per claim. The own
     * path comes before the alternatives and the last member varies fastest, which puts the option
     * asking for every claim under its own path first.
     */
    public List<List<Integer>> claimSetOptionIndexes() {
        List<List<Integer>> baseOptions = optionsByClaimSetId();
        boolean alternatives = claimSpecs.stream()
                .anyMatch(claimSpec -> !claimSpec.alternativePaths().isEmpty());
        if (baseOptions.isEmpty()) {
            if (!alternatives) {
                return List.of();
            }
            baseOptions = List.of(IntStream.range(0, claimSpecs.size()).boxed().toList());
        }

        int[] offsets = new int[claimSpecs.size()];
        int offset = 0;
        for (int i = 0; i < claimSpecs.size(); i++) {
            offsets[i] = offset;
            offset += claimSpecs.get(i).alternativePaths().size() + 1;
        }

        List<List<Integer>> options = new ArrayList<>();
        for (List<Integer> baseOption : baseOptions) {
            options.addAll(pathCombinations(baseOption, offsets));
        }
        return options;
    }

    /** Builds one option per claim set id, as indexes into {@link #claimSpecs()}. */
    private List<List<Integer>> optionsByClaimSetId() {
        SortedSet<String> claimSetIds = new TreeSet<>();
        for (ClaimSpec claimSpec : claimSpecs) {
            claimSetIds.addAll(claimSpec.claimSetIds());
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

    /** Combines the path choices of the given specs into every option, as indexes into {@link #requestedClaims()}. */
    private List<List<Integer>> pathCombinations(List<Integer> specIndexes, int[] offsets) {
        List<List<Integer>> combinations = new ArrayList<>();
        combinations.add(List.of());
        for (int specIndex : specIndexes) {
            int pathCount = claimSpecs.get(specIndex).alternativePaths().size() + 1;
            List<List<Integer>> extended = new ArrayList<>();
            for (List<Integer> combination : combinations) {
                for (int choice = 0; choice < pathCount; choice++) {
                    List<Integer> next = new ArrayList<>(combination);
                    next.add(offsets[specIndex] + choice);
                    extended.add(next);
                }
            }
            combinations = extended;
        }
        return combinations;
    }
}
