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
package de.arbeitsagentur.keycloak.oid4vp.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.utils.StringUtil;

/**
 * Utility methods for OID4VP identity provider mappers.
 *
 * <p>Provides claim extraction from the {@link BrokeredIdentityContext} populated by
 * {@link de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpCallbackProcessor}, credential format
 * matching, and value conversion. Supports nested claim paths (DCQL-style {@code address/street}),
 * mDoc namespace-prefixed keys, and multivalued claims.
 */
public final class Oid4vpMapperUtils {

    private static final Logger LOG = Logger.getLogger(Oid4vpMapperUtils.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String PATH_SEPARATOR = "/";

    public static final String CONTEXT_CLAIMS_KEY = "oid4vp_claims";
    public static final String CONTEXT_ISSUER_KEY = "oid4vp_issuer";
    public static final String CONTEXT_SUBJECT_KEY = "oid4vp_subject";
    public static final String CONTEXT_PRESENTATION_TYPE_KEY = "oid4vp_presentation_type";
    public static final String CONTEXT_CREDENTIAL_TYPE_KEY = "oid4vp_credential_type";

    private Oid4vpMapperUtils() {}

    /** Extracts a claim value from the brokered identity context by claim path. */
    @SuppressWarnings("unchecked")
    public static Object getClaimValue(BrokeredIdentityContext context, String claimPath) {
        Map<String, Object> claims =
                (Map<String, Object>) context.getContextData().get(CONTEXT_CLAIMS_KEY);
        if (claims == null) {
            LOG.debugf("No oid4vp_claims in context data");
            return null;
        }

        return getNestedValue(claims, claimPath);
    }

    /** Checks if a mapper's credential format/type filter matches the current presentation. */
    public static boolean matchesCredential(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String mapperFormat = mapperModel.getConfig().get(Oid4vpMapperConfigProperties.CREDENTIAL_FORMAT);
        String mapperType = mapperModel.getConfig().get(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE);

        if (StringUtil.isNotBlank(mapperFormat)) {
            String presentationType = (String) context.getContextData().get(CONTEXT_PRESENTATION_TYPE_KEY);
            String contextFormat = formatFromPresentationType(presentationType);
            if (!mapperFormat.equals(contextFormat)) {
                return false;
            }
        }

        if (StringUtil.isNotBlank(mapperType)) {
            String contextType = (String) context.getContextData().get(CONTEXT_CREDENTIAL_TYPE_KEY);
            if (!mapperType.equals(contextType)) {
                return false;
            }
        }

        return true;
    }

    private static String formatFromPresentationType(String presentationType) {
        if (PresentationType.MDOC.name().equals(presentationType)) {
            return Oid4vpConstants.FORMAT_MSO_MDOC;
        } else if (PresentationType.SD_JWT.name().equals(presentationType)) {
            return Oid4vpConstants.FORMAT_SD_JWT_VC;
        }
        return presentationType;
    }

    /**
     * Converts a claim value to a string. If the value is a list, returns the first element's
     * string representation. Returns {@code null} for null, empty list, or empty string values.
     */
    public static String toStringValue(Object claimValue) {
        return toStringValue(claimValue, false);
    }

    /**
     * Converts a claim value to a string, optionally parsing JSON scalar/array strings first.
     * If the value is a list, returns the first element's string representation.
     */
    public static String toStringValue(Object claimValue, boolean parseJsonStrings) {
        Object normalizedValue = normalizeClaimValue(claimValue, parseJsonStrings);
        if (normalizedValue == null) return null;

        if (normalizedValue instanceof List<?> list) {
            if (list.isEmpty()) return null;
            return list.get(0).toString();
        }

        return normalizedValue.toString();
    }

    /**
     * Converts a claim value to a list of strings for multi-valued Keycloak attributes.
     * Scalar values are wrapped in a single-element list.
     */
    public static List<String> toStringList(Object claimValue) {
        return toStringList(claimValue, false);
    }

    /**
     * Converts a claim value to a list of strings for multi-valued Keycloak attributes, optionally
     * parsing JSON scalar/array strings first. Scalar values are wrapped in a single-element list.
     */
    public static List<String> toStringList(Object claimValue, boolean parseJsonStrings) {
        Object normalizedValue = normalizeClaimValue(claimValue, parseJsonStrings);
        if (normalizedValue == null) return new ArrayList<>();

        if (normalizedValue instanceof List<?> list) {
            return list.stream().map(Object::toString).collect(Collectors.toList());
        }

        ArrayList<String> result = new ArrayList<>(1);
        result.add(normalizedValue.toString());
        return result;
    }

    /**
     * Deep-copies a claims map so that all nested Maps and Lists are mutable standard types
     * (HashMap/ArrayList). This is required because Keycloak's {@code SerializedBrokeredIdentityContext}
     * round-trips context data through JSON and fails when it encounters immutable collection types.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toMutableClaims(Map<String, Object> claims) {
        if (claims == null) return null;
        Map<String, Object> result = new HashMap<>(claims.size());
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            result.put(entry.getKey(), toMutableValue(entry.getValue()));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Object toMutableValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new HashMap<>(map.size());
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                result.put(String.valueOf(entry.getKey()), toMutableValue(entry.getValue()));
            }
            return result;
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>(list.size());
            for (Object item : list) {
                result.add(toMutableValue(item));
            }
            return result;
        }
        return value;
    }

    /**
     * Navigates a claims map by path, supporting nested objects, mDoc namespaced keys,
     * JSON-encoded mDoc values, and DCQL {@code null} array traversal. Tries exact match, then nested
     * path, then suffix match. For slash paths, if the base claim resolves to a scalar or JSON string
     * instead of a nested object/array, the raw base value is returned as a fallback.
     */
    public static Object getNestedValue(Map<String, Object> claims, String claimPath) {
        if (claims == null || claimPath == null) return null;

        Object resolvedValue = findDirectClaimValue(claims, claimPath);
        if (resolvedValue != null) {
            return resolvedValue;
        }

        int separatorIndex = claimPath.indexOf(PATH_SEPARATOR);
        if (separatorIndex < 0) {
            return null;
        }

        String baseClaimPath = claimPath.substring(0, separatorIndex);
        List<Object> baseClaimValues = findClaimCandidates(claims, baseClaimPath);
        if (baseClaimValues.isEmpty()) {
            return null;
        }

        String[] nestedParts = claimPath.substring(separatorIndex + 1).split(PATH_SEPARATOR);
        Object fallbackValue = null;
        for (Object baseClaimValue : baseClaimValues) {
            Object nestedValue = extractNestedValue(baseClaimValue, nestedParts);
            if (nestedValue != null) {
                return nestedValue;
            }
            if (fallbackValue == null && isScalarFallback(baseClaimValue)) {
                fallbackValue = baseClaimValue;
            }
        }

        return fallbackValue;
    }

    private static Object normalizeClaimValue(Object value, boolean parseJsonStrings) {
        if (value instanceof Map<?, ?> map && map.isEmpty()) {
            return null;
        }
        if (parseJsonStrings && value instanceof String stringValue) {
            ParsedJson parsed = tryParseJson(stringValue);
            if (!parsed.success()) {
                return value;
            }
            Object parsedValue = parsed.value();
            if (parsedValue == null) {
                return null;
            }
            if (parsedValue instanceof List<?>
                    || parsedValue instanceof String
                    || parsedValue instanceof Number
                    || parsedValue instanceof Boolean) {
                return parsedValue;
            }
        }
        return value;
    }

    private static Object findDirectClaimValue(Map<String, Object> claims, String claimPath) {
        List<Object> candidates = findClaimCandidates(claims, claimPath);
        return candidates.isEmpty() ? null : candidates.get(0);
    }

    private static List<Object> findClaimCandidates(Map<String, Object> claims, String claimPath) {
        List<Object> candidates = new ArrayList<>();
        if (claims.containsKey(claimPath)) {
            candidates.add(claims.get(claimPath));
        }

        Object navigatedValue = navigateStructuredPath(claims, claimPath.split(PATH_SEPARATOR));
        if (navigatedValue != null && !candidates.contains(navigatedValue)) {
            candidates.add(navigatedValue);
        }

        String suffix = PATH_SEPARATOR + claimPath;
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            Object suffixValue = entry.getValue();
            if (entry.getKey().endsWith(suffix) && !candidates.contains(suffixValue)) {
                candidates.add(suffixValue);
            }
        }
        return candidates;
    }

    private static Object extractNestedValue(Object baseClaimValue, String[] nestedParts) {
        Object parsedBaseValue = parseJsonValueIfPossible(baseClaimValue);
        if (parsedBaseValue == null) {
            return null;
        }
        return navigateStructuredPath(parsedBaseValue, nestedParts);
    }

    private static Object navigateStructuredPath(Object value, String[] pathParts) {
        Object current = value;
        for (String part : pathParts) {
            if ("null".equals(part)) {
                if (!(current instanceof List<?>)) {
                    return null;
                }
            } else if (current instanceof Map<?, ?> map) {
                current = map.get(part);
                if (current == null) {
                    return null;
                }
            } else {
                Integer index = parseArrayIndex(part);
                if (index == null || !(current instanceof List<?> list)) {
                    return null;
                }
                if (index < 0 || index >= list.size()) {
                    return null;
                }
                current = list.get(index);
            }
        }
        return current;
    }

    private static Object parseJsonValueIfPossible(Object value) {
        if (!(value instanceof String stringValue)) {
            return value;
        }
        ParsedJson parsed = tryParseJson(stringValue);
        return parsed.success() ? parsed.value() : value;
    }

    private static boolean isScalarFallback(Object value) {
        return !(value instanceof Map<?, ?>) && !(value instanceof List<?>);
    }

    private static Integer parseArrayIndex(String segment) {
        try {
            int index = Integer.parseInt(segment);
            return index >= 0 ? index : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static ParsedJson tryParseJson(String value) {
        try {
            return new ParsedJson(true, OBJECT_MAPPER.readValue(value, Object.class));
        } catch (Exception e) {
            return new ParsedJson(false, null);
        }
    }

    private record ParsedJson(boolean success, Object value) {}
}
