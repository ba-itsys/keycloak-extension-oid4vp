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
 * <p>{@code claimSetIds} lists the DCQL claim sets this claim belongs to. A claim without ids is
 * part of every generated claim set and therefore always requested.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.3">OID4VP 1.0 §6.3 — Claims Query</a>
 */
public record ClaimSpec(String namespace, String path, List<String> claimSetIds) {

    private static final String CLAIM_SET_ID_SEPARATOR = ",";

    public ClaimSpec {
        claimSetIds = claimSetIds != null ? List.copyOf(claimSetIds) : List.of();
    }

    /** A claim of an SD-JWT credential, addressed by a dot notation path over the claims JSON. */
    public static ClaimSpec sdJwt(String path, List<String> claimSetIds) {
        return new ClaimSpec(null, path, claimSetIds);
    }

    public static ClaimSpec sdJwt(String path) {
        return sdJwt(path, List.of());
    }

    /** A claim of an mDoc credential: a data element of the given namespace. */
    public static ClaimSpec mdoc(String namespace, String path, List<String> claimSetIds) {
        return new ClaimSpec(namespace, path, claimSetIds);
    }

    public static ClaimSpec mdoc(String namespace, String path) {
        return mdoc(namespace, path, List.of());
    }

    /** Parses a comma-separated mapper config value into a list of claim set ids. */
    public static List<String> parseClaimSetIds(String rawClaimSetIds) {
        if (StringUtil.isBlank(rawClaimSetIds)) {
            return List.of();
        }
        return Arrays.stream(rawClaimSetIds.split(CLAIM_SET_ID_SEPARATOR))
                .map(String::trim)
                .filter(StringUtil::isNotBlank)
                .distinct()
                .toList();
    }

    /** The parsed claim path, or {@code null} when the configured path is malformed. */
    public ClaimPath claimPath() {
        return ClaimPath.parse(path);
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
