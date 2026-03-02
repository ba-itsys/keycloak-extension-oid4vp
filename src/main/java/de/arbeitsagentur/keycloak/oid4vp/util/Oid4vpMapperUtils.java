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
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.utils.StringUtil;

public final class Oid4vpMapperUtils {

    private static final Logger LOG = Logger.getLogger(Oid4vpMapperUtils.class);

    public static final String CONTEXT_CLAIMS_KEY = "oid4vp_claims";
    public static final String CONTEXT_ISSUER_KEY = "oid4vp_issuer";
    public static final String CONTEXT_SUBJECT_KEY = "oid4vp_subject";
    public static final String CONTEXT_PRESENTATION_TYPE_KEY = "oid4vp_presentation_type";
    public static final String CONTEXT_CREDENTIAL_TYPE_KEY = "oid4vp_credential_type";

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
        if ("MDOC".equals(presentationType)) {
            return Oid4vpConstants.FORMAT_MSO_MDOC;
        } else if ("SD_JWT".equals(presentationType)) {
            return Oid4vpConstants.FORMAT_SD_JWT_VC;
        }
        return presentationType;
    }

    public static Object getNestedValue(Map<String, Object> claims, String claimPath) {
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
}
