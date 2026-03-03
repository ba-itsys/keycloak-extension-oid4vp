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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.utils.StringUtil;

public record ClaimSpec(String path, boolean optional, boolean multivalued) {

    private static final String PATH_SEPARATOR = "/";

    public ClaimSpec(String path) {
        this(path, false, false);
    }

    public ClaimSpec(String path, boolean optional) {
        this(path, optional, false);
    }

    public List<Object> toDcqlPath(String format, String type) {
        if (StringUtil.isBlank(path)) {
            return List.of();
        }
        if (path.contains(PATH_SEPARATOR)) {
            return Arrays.stream(path.split(PATH_SEPARATOR))
                    .map(ClaimSpec::parsePathSegment)
                    .collect(Collectors.toList());
        }
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equals(format) && type != null) {
            return List.of(type, path);
        }
        return List.of(path);
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
