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
package de.arbeitsagentur.keycloak.oid4vp;

import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;

public final class Oid4vpMapperUtils {

    private static final Logger LOG = Logger.getLogger(Oid4vpMapperUtils.class);

    static final String CONTEXT_CLAIMS_KEY = "oid4vp_claims";

    private Oid4vpMapperUtils() {}

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

    static Object getNestedValue(Map<String, Object> claims, String claimPath) {
        if (claims == null || claimPath == null) return null;

        // Try exact key match first (handles mDoc flat keys like "namespace/element")
        Object direct = claims.get(claimPath);
        if (direct != null) return direct;

        // Fall back to nested path navigation
        String[] pathParts = claimPath.split("/");
        Object current = claims;
        for (String part : pathParts) {
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
                if (current == null) return null;
            } else {
                return null;
            }
        }
        return current;
    }
}
