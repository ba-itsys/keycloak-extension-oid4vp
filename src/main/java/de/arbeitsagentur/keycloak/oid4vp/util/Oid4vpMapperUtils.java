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
        Object normalizedValue = normalizeClaimValue(claimValue);
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
        Object normalizedValue = normalizeClaimValue(claimValue);
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
     * and DCQL {@code null} array traversal. Tries exact match, then nested path, then suffix match.
     */
    public static Object getNestedValue(Map<String, Object> claims, String claimPath) {
        if (claims == null || claimPath == null) return null;

        // Try exact key match first (handles mDoc flat keys like "namespace/element")
        if (claims.containsKey(claimPath)) {
            return claims.get(claimPath);
        }

        // Fall back to nested path navigation (supports DCQL-style null for array traversal)
        String[] pathParts = claimPath.split("/");
        Object current = claims;
        for (String part : pathParts) {
            if ("null".equals(part)) {
                // DCQL null: select all elements of the current array
                if (current instanceof List<?>) {
                    continue;
                }
                current = null;
                break;
            } else if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
                if (current == null) break;
            } else {
                current = null;
                break;
            }
        }
        if (current != null) return current;

        // Fall back to suffix match for mDoc namespaced keys (e.g. "family_name" matches
        // "eu.europa.ec.eudi.pid.1/family_name")
        String suffix = "/" + claimPath;
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getKey().endsWith(suffix)) {
                return entry.getValue();
            }
        }

        return null;
    }

    private static Object normalizeClaimValue(Object value) {
        if (value instanceof Map<?, ?> map && map.isEmpty()) {
            return null;
        }
        return value;
    }
}
