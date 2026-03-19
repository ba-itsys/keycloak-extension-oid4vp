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
 * For mDoc credentials, the namespace is automatically prepended when building DCQL paths.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.4">OID4VP 1.0 §5.4 — DCQL Query</a>
 */
public record ClaimSpec(String path, boolean optional, boolean multivalued) {

    private static final String PATH_SEPARATOR = "/";

    public ClaimSpec(String path) {
        this(path, false, false);
    }

    public ClaimSpec(String path, boolean optional) {
        this(path, optional, false);
    }

    /** Converts this claim path to a DCQL {@code claims[].path} array for the given credential format and type. */
    public List<Object> toDcqlPath(String format, String type) {
        if (StringUtil.isBlank(path)) {
            return List.of();
        }
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equals(format) && type != null) {
            String requestedPath =
                    path.contains(PATH_SEPARATOR) ? path.substring(0, path.indexOf(PATH_SEPARATOR)) : path;
            if (multivalued) {
                return listWithNullableEntries(type, parsePathSegment(requestedPath), null);
            }
            return List.of(type, parsePathSegment(requestedPath));
        }
        if (path.contains(PATH_SEPARATOR)) {
            List<Object> segments = Arrays.stream(path.split(PATH_SEPARATOR))
                    .map(ClaimSpec::parsePathSegment)
                    .collect(Collectors.toCollection(ArrayList::new));
            if (multivalued) {
                segments.add(null);
            }
            return segments;
        }
        if (multivalued) {
            return listWithNullableEntries(path, null);
        }
        return List.of(path);
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
