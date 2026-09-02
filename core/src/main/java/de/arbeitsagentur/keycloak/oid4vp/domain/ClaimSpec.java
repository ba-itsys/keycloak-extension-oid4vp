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

import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimPath;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.keycloak.utils.StringUtil;

/**
 * Specification of a single claim to request within a DCQL credential query.
 *
 * <p>{@code path} uses the {@link ClaimPath} dot notation shared with the OID4VP mappers
 * ({@code address.locality}, {@code nationalities[]}). For mDoc claims, {@code namespace} names
 * the ISO 18013-5 namespace and the first path step names the data element; deeper steps only
 * address into the element value on the mapper side and are not part of the DCQL query.
 *
 * <p>{@code alternativePaths} names claims that stand in for the path when a credential does not
 * carry it, in preference order: issuers name the same claim differently, so a mapper reading the
 * German PID's {@code birth_family_name} also accepts {@code birth_name}. Every alternative is
 * requested as a claim of its own, and the claim sets ask for exactly one of the path and its
 * alternatives per option. {@link #expand()} turns the spec into those single-path claims.
 *
 * <p>{@code claimSetIds} lists the DCQL claim sets this claim belongs to. A claim without ids is
 * part of every generated claim set and therefore always requested.
 *
 * <p>{@code id} is the DCQL claim id the claim is requested under, derived from the mapper name
 * so that the {@code claim_sets} of a generated query read like the configuration that produced
 * them. It is null for claims added without a mapper, which the query builder numbers instead.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public record ClaimSpec(
        String id, String namespace, String path, List<String> alternativePaths, List<String> claimSetIds) {

    private static final String LIST_SEPARATOR = ",";
    private static final String ALTERNATIVE_ID_SEPARATOR = "-";

    public ClaimSpec {
        alternativePaths = alternativePaths != null ? List.copyOf(alternativePaths) : List.of();
        claimSetIds = claimSetIds != null ? List.copyOf(claimSetIds) : List.of();
    }

    /** A claim of an SD-JWT credential, addressed by a dot notation path over the claims JSON. */
    public static ClaimSpec sdJwt(String path, List<String> claimSetIds) {
        return new ClaimSpec(null, null, path, List.of(), claimSetIds);
    }

    public static ClaimSpec sdJwt(String path) {
        return sdJwt(path, List.of());
    }

    /** A claim of an mDoc credential: a data element of the given namespace. */
    public static ClaimSpec mdoc(String namespace, String path, List<String> claimSetIds) {
        return new ClaimSpec(null, namespace, path, List.of(), claimSetIds);
    }

    public static ClaimSpec mdoc(String namespace, String path) {
        return mdoc(namespace, path, List.of());
    }

    /** The same claim requested under the given DCQL claim id. */
    public ClaimSpec withId(String id) {
        return new ClaimSpec(id, namespace, path, alternativePaths, claimSetIds);
    }

    /** The same claim, accepting the given paths in their order when the path is not presented. */
    public ClaimSpec withAlternativePaths(List<String> alternativePaths) {
        return new ClaimSpec(id, namespace, path, alternativePaths, claimSetIds);
    }

    /** Parses a comma-separated mapper config value into a list of claim set ids. */
    public static List<String> parseClaimSetIds(String rawClaimSetIds) {
        return parseList(rawClaimSetIds);
    }

    /** Parses a comma-separated mapper config value into a list of claim paths. */
    public static List<String> parseAlternativePaths(String rawAlternativePaths) {
        return parseList(rawAlternativePaths);
    }

    private static List<String> parseList(String rawList) {
        if (StringUtil.isBlank(rawList)) {
            return List.of();
        }
        return Arrays.stream(rawList.split(LIST_SEPARATOR))
                .map(String::trim)
                .filter(StringUtil::isNotBlank)
                .distinct()
                .toList();
    }

    /** The parsed claim path, or {@code null} when the configured path is malformed. */
    public ClaimPath claimPath() {
        return ClaimPath.parse(path);
    }

    /** Whether the path and every alternative path parse. */
    public boolean pathsWellFormed() {
        return claimPath() != null
                && alternativePaths.stream().allMatch(alternative -> ClaimPath.parse(alternative) != null);
    }

    /**
     * The claims this spec requests: the path first, then every alternative, each without further
     * alternatives and each a member of the same claim sets. An alternative is requested under the
     * spec's id followed by the slugged alternative path, so {@code birth_name} of a mapper named
     * {@code birth-name} reads {@code birth-name-birth_name} in the claim sets.
     */
    public List<ClaimSpec> expand() {
        List<ClaimSpec> claims = new ArrayList<>();
        claims.add(new ClaimSpec(id, namespace, path, List.of(), claimSetIds));
        for (String alternative : alternativePaths) {
            String alternativeId = id == null ? null : id + ALTERNATIVE_ID_SEPARATOR + DcqlId.slug(alternative);
            claims.add(new ClaimSpec(alternativeId, namespace, alternative, List.of(), claimSetIds));
        }
        return claims;
    }

    /**
     * Converts this claim to a DCQL {@code claims[].path} pointer. SD-JWT paths map step by step
     * (field to string, all elements to null, first element to 0). mDoc paths are always
     * {@code [namespace, element]}: mDoc claims cannot be requested below element level.
     */
    public List<Object> toDcqlPath() {
        ClaimPath claimPath = claimPath();
        if (claimPath == null) {
            return List.of();
        }
        if (namespace != null) {
            return Arrays.asList(namespace, claimPath.steps().get(0).field());
        }
        List<Object> pointer = new ArrayList<>();
        for (ClaimPath.Step step : claimPath.steps()) {
            switch (step.kind()) {
                case FIELD -> pointer.add(step.field());
                case ALL_ELEMENTS -> pointer.add(null);
                case FIRST_ELEMENT -> pointer.add(0);
            }
        }
        return pointer;
    }
}
