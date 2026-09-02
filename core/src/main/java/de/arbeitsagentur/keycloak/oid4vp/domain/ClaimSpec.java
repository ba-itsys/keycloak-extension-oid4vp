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

/**
 * One claim to request in a DCQL credential query.
 *
 * <p>{@code path} uses the {@link ClaimPath} dot notation of the OID4VP mappers, for example
 * {@code address.locality} or {@code nationalities[]}. For an mDoc claim, {@code namespace} names
 * the ISO 18013-5 namespace and the first path step names the data element. Deeper steps address
 * into the element value on the mapper side. They are not part of the DCQL query.
 *
 * <p>{@code alternativePaths} are the claims the mapper reads, in that order, when the credential
 * does not carry {@code path}, because issuers name the same claim differently: the German PID has
 * {@code birth_name} where the EUDI PID has {@code birth_family_name}. Each alternative becomes a
 * claim of its own in the DCQL query, and every claim set option asks for exactly one of them.
 *
 * <p>{@code claimSetIds} lists the DCQL claim sets this claim belongs to. A claim without ids is
 * part of every generated claim set and is therefore always requested.
 *
 * <p>{@code id} is the DCQL claim id and comes from the mapper name, so that the generated
 * {@code claim_sets} read like the configuration. A claim without a mapper has no id and is
 * numbered by the query builder.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public record ClaimSpec(
        String id, String namespace, String path, List<String> alternativePaths, List<String> claimSetIds) {

    private static final String ALTERNATIVE_ID_SEPARATOR = "-";

    public ClaimSpec {
        alternativePaths = alternativePaths != null ? List.copyOf(alternativePaths) : List.of();
        claimSetIds = claimSetIds != null ? List.copyOf(claimSetIds) : List.of();
    }

    public static ClaimSpec sdJwt(String path, List<String> claimSetIds) {
        return new ClaimSpec(null, null, path, List.of(), claimSetIds);
    }

    public static ClaimSpec sdJwt(String path) {
        return sdJwt(path, List.of());
    }

    public static ClaimSpec mdoc(String namespace, String path, List<String> claimSetIds) {
        return new ClaimSpec(null, namespace, path, List.of(), claimSetIds);
    }

    public static ClaimSpec mdoc(String namespace, String path) {
        return mdoc(namespace, path, List.of());
    }

    public ClaimSpec withId(String id) {
        return new ClaimSpec(id, namespace, path, alternativePaths, claimSetIds);
    }

    public ClaimSpec withAlternativePaths(List<String> alternativePaths) {
        return new ClaimSpec(id, namespace, path, alternativePaths, claimSetIds);
    }

    public static List<String> parseClaimSetIds(String rawClaimSetIds) {
        return ConfigList.parse(rawClaimSetIds);
    }

    public static List<String> parseAlternativePaths(String rawAlternativePaths) {
        return ConfigList.parse(rawAlternativePaths);
    }

    /** Parses the configured path. Returns null when it is malformed, which callers treat as a misconfiguration. */
    public ClaimPath claimPath() {
        return ClaimPath.parse(path);
    }

    public boolean pathsWellFormed() {
        return claimPath() != null
                && alternativePaths.stream().allMatch(alternative -> ClaimPath.parse(alternative) != null);
    }

    /**
     * Expands this spec into one claim per path, because DCQL can only request a single path per
     * claim. The own path comes first, then each alternative. All of them keep the claim set ids.
     * An alternative is named after the spec id plus its slugged path, so {@code birth_name} on a
     * mapper named {@code birth-name} becomes {@code birth-name-birth_name}.
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
     * Maps the configured path to the DCQL {@code claims[].path} pointer. An mDoc pointer is
     * always {@code [namespace, element]}, because mDoc claims cannot be requested below element
     * level.
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
