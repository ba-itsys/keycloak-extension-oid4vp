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
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.utils.StringUtil;

/**
 * Specification of a single claim to request within a DCQL credential query.
 *
 * <p>The {@code path} uses {@code /} as separator for nested claims (e.g. {@code address/street}).
 * For mDoc credentials, a dotted first segment is treated as an explicit namespace (e.g.
 * {@code org.iso.18013.5.1/given_name}); otherwise the doctype is used as namespace.
 *
 * <p>{@code claimSetIds} lists the DCQL claim sets this claim belongs to. A claim without ids is
 * part of every generated claim set and therefore always requested.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">OID4VP 1.0 §6.4 — Claims Query</a>
 */
public record ClaimSpec(String path, List<String> claimSetIds, boolean multivalued) {

    private static final String PATH_SEPARATOR = "/";
    private static final String CLAIM_SET_ID_SEPARATOR = ",";

    public ClaimSpec {
        claimSetIds = claimSetIds != null ? List.copyOf(claimSetIds) : List.of();
    }

    public ClaimSpec(String path) {
        this(path, List.of(), false);
    }

    public ClaimSpec(String path, List<String> claimSetIds) {
        this(path, claimSetIds, false);
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

    /** Converts this claim path to a DCQL {@code claims[].path} array for the given credential format and type. */
    public List<Object> toDcqlPath(String format, String type) {
        if (StringUtil.isBlank(path)) {
            return List.of();
        }
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equals(format) && type != null) {
            return toMdocPath(type);
        }
        if (path.contains(PATH_SEPARATOR)) {
            List<Object> segments = Arrays.stream(path.split(PATH_SEPARATOR))
                    .map(ClaimSpec::parsePathSegment)
                    .collect(Collectors.toCollection(ArrayList::new));
            if (multivalued && !endsWithArraySelector(segments)) {
                segments.add(null);
            }
            return segments;
        }
        if (multivalued) {
            return listWithNullableEntries(path, null);
        }
        return List.of(path);
    }

    /**
     * Builds the two-element mDoc path {@code [namespace, element]}. mDoc namespaces are
     * reverse-domain identifiers, so a dotted first path segment selects an explicit namespace;
     * otherwise the doctype serves as namespace and only the first segment of a nested path is
     * requested (mDoc claims cannot be requested below element level).
     */
    private List<Object> toMdocPath(String doctype) {
        String namespace = doctype;
        String elementPath = path;
        int separatorIndex = path.indexOf(PATH_SEPARATOR);
        if (separatorIndex >= 0 && path.substring(0, separatorIndex).contains(".")) {
            namespace = path.substring(0, separatorIndex);
            elementPath = path.substring(separatorIndex + 1);
        }
        String element = elementPath.contains(PATH_SEPARATOR)
                ? elementPath.substring(0, elementPath.indexOf(PATH_SEPARATOR))
                : elementPath;
        return List.of(namespace, parsePathSegment(element));
    }

    private static boolean endsWithArraySelector(List<Object> segments) {
        return !segments.isEmpty() && segments.get(segments.size() - 1) == null;
    }

    private static List<Object> listWithNullableEntries(Object... values) {
        return new ArrayList<>(Arrays.asList(values));
    }

    private static Object parsePathSegment(String segment) {
        if ("null".equals(segment)) {
            return null;
        }
        try {
            int index = Integer.parseInt(segment);
            if (index >= 0) {
                return index;
            }
        } catch (NumberFormatException ignored) {
        }
        return segment;
    }
}
