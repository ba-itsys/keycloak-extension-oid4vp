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
 * Specification of one credential entry of a DCQL query: its format, the credential types it
 * accepts and the claims it requests, aggregated from the identity provider mappers.
 *
 * <p>An SD-JWT entry may accept several credential types, which DCQL requests as one
 * {@code vct_values} array: a wallet answers with a credential of any of them. That covers
 * credentials whose type identifier differs per country or rulebook version, such as the EUDI PID
 * {@code urn:eudi:pid:1} and the German PID {@code urn:eudi:pid:de:1}. An mDoc entry names exactly
 * one doctype, as DCQL defines {@code doctype_value} as a single string.
 *
 * @param format the credential format ({@code dc+sd-jwt} or {@code mso_mdoc})
 * @param types the accepted credential type identifiers (VCTs for SD-JWT, the doctype for mDoc), in
 *     the order they are requested
 * @param claimSpecs the claims to request within this credential, one per mapper
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

    /** A credential of a single type. */
    public CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {
        this(format, List.of(type), claimSpecs);
    }

    /** The first accepted type, which derives the default credential id. */
    public String firstType() {
        return types.get(0);
    }

    /** Parses the comma-separated credential types of a mapper. */
    public static List<String> parseTypes(String rawTypes) {
        return ConfigList.parse(rawTypes);
    }

    /**
     * The claims the DCQL query requests, one per path: every claim spec expanded into its path and
     * alternative paths, in claim spec order. {@link #claimSetOptionIndexes()} indexes this list.
     */
    public List<ClaimSpec> requestedClaims() {
        return claimSpecs.stream()
                .flatMap(claimSpec -> claimSpec.expand().stream())
                .toList();
    }

    /**
     * Computes the DCQL {@code claim_sets} options as indexes into {@link #requestedClaims()}.
     *
     * <p>The claim set ids form the base options: one per distinct id, ordered lexicographically by
     * id, with claims without ids members of every option. Alternative paths then multiply every
     * base option: each becomes one option per combination of the path choices of its members, so
     * an option requests exactly one of a claim's path and alternatives. The combinations are
     * ordered with the paths themselves first and the last member's alternatives varying fastest,
     * so the first option is the one asking for every claim under its own path.
     *
     * <p>An empty result means no {@code claim_sets} entry is generated and all claims are required.
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

    /** One option per claim set id as indexes into {@link #claimSpecs()}; empty without ids. */
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

    /** The cross product of the path choices of the option's claim specs, as requested claim indexes. */
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
