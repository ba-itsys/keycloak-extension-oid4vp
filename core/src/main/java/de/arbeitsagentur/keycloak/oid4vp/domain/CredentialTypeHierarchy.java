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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Which types a credential counts as. A credential of a derived type also answers a request for
 * its base type. The German PID {@code urn:eudi:pid:de:1} answers a request for
 * {@code urn:eudi:pid:1}. The other direction never applies.
 *
 * <p>The relationship comes from two places. An SD-JWT VC can list additional types in its
 * {@code aka_vcts} claim (SD-JWT VC, section 2.2.2.2). For a URN type the identifier itself tells
 * it. {@code urn:eudi:pid:de:1} is {@code urn:eudi:pid:1} with a qualifier inserted before the
 * version. That is how the ARF names national PID types. Type metadata is not looked up. PID
 * types are URNs and have no metadata document.
 *
 * <p>This only says what a credential is. The signature and trust checks decide whether the
 * issuer was allowed to issue it (SD-JWT VC, section 6.6).
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/">SD-JWT VC</a>
 */
public final class CredentialTypeHierarchy {

    public static final String AKA_VCTS_CLAIM = "aka_vcts";

    private static final String URN_SCHEME = "urn";
    private static final String URN_SEPARATOR = ":";
    /** Scheme, namespace, name, at least one qualifier, version. */
    private static final int MIN_DERIVED_URN_SEGMENTS = 5;

    private static final int NAME_SEGMENTS = 3;

    private CredentialTypeHierarchy() {}

    public static List<String> alsoKnownAsTypes(JsonNode payload) {
        JsonNode claim = payload != null ? payload.get(AKA_VCTS_CLAIM) : null;
        if (claim == null || !claim.isArray()) {
            return List.of();
        }
        List<String> types = new ArrayList<>();
        claim.forEach(element -> {
            if (element.isTextual()) {
                types.add(element.textValue());
            }
        });
        return types;
    }

    /**
     * Lists every type this credential counts as, so a request can be matched against all of them.
     * The type itself comes first, then its {@code aka_vcts} types, then the URN base types of
     * each, nearest first.
     */
    public static List<String> typesOf(String type, List<String> alsoKnownAs) {
        Set<String> types = new LinkedHashSet<>();
        if (type != null) {
            types.add(type);
        }
        if (alsoKnownAs != null) {
            alsoKnownAs.stream().filter(aka -> aka != null && !aka.isBlank()).forEach(types::add);
        }
        for (String named : List.copyOf(types)) {
            types.addAll(urnAncestors(named));
        }
        return List.copyOf(types);
    }

    public static boolean isOfType(String type, List<String> alsoKnownAs, String requestedType) {
        return requestedType != null && typesOf(type, alsoKnownAs).contains(requestedType);
    }

    /**
     * Returns the base types of a URN type, nearest first, so {@code urn:eudi:pid:de:bavaria:1}
     * yields {@code urn:eudi:pid:de:1} and then {@code urn:eudi:pid:1}. The result is empty unless
     * the type is a URN with at least one qualifier and a numeric version.
     */
    public static List<String> urnAncestors(String type) {
        if (type == null) {
            return List.of();
        }
        String[] segments = type.split(URN_SEPARATOR, -1);
        if (segments.length < MIN_DERIVED_URN_SEGMENTS
                || !URN_SCHEME.equalsIgnoreCase(segments[0])
                || !isVersion(segments[segments.length - 1])) {
            return List.of();
        }
        List<String> ancestors = new ArrayList<>();
        String version = segments[segments.length - 1];
        for (int qualifiers = segments.length - 2; qualifiers >= NAME_SEGMENTS; qualifiers--) {
            ancestors.add(
                    String.join(URN_SEPARATOR, List.of(segments).subList(0, qualifiers)) + URN_SEPARATOR + version);
        }
        return ancestors;
    }

    private static boolean isVersion(String segment) {
        return !segment.isEmpty() && segment.chars().allMatch(Character::isDigit);
    }
}
