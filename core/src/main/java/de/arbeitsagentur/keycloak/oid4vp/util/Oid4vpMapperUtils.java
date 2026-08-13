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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.util.JsonSerialization;

/**
 * Shared context-data conventions between the OID4VP callback processing and the identity
 * provider mappers.
 *
 * <p>The verified claims are exposed as a claims JSON tree under {@link #CONTEXT_CLAIMS_KEY},
 * matching the design of upstream Keycloak's OID4VP mappers. mDoc claims arrive from the verifier
 * already nested under their namespace: {@code {"org.iso.18013.5.1": {"given_name": "Erika"}}}.
 */
public final class Oid4vpMapperUtils {

    public static final String CONTEXT_CLAIMS_KEY = "OID4VP_CREDENTIAL_CLAIMS";
    public static final String CONTEXT_ISSUER_KEY = "oid4vp_issuer";
    public static final String CONTEXT_SUBJECT_KEY = "oid4vp_subject";
    public static final String CONTEXT_CREDENTIAL_FORMAT_KEY = "oid4vp_credential_format";
    public static final String CONTEXT_CREDENTIAL_TYPE_KEY = "oid4vp_credential_type";

    private Oid4vpMapperUtils() {}

    /**
     * The claims JSON of the verified presentation. A context that was serialized into the
     * authentication session restores the tree as plain maps, so the value is coerced back.
     */
    public static JsonNode claimsNode(BrokeredIdentityContext context) {
        Object claims = context.getContextData().get(CONTEXT_CLAIMS_KEY);
        if (claims == null) {
            return null;
        }
        if (claims instanceof JsonNode node) {
            return node;
        }
        return JsonSerialization.mapper.valueToTree(claims);
    }

    /** Builds the claims JSON of a verified credential. */
    public static JsonNode toClaimsNode(VerifiedCredential credential) {
        return JsonSerialization.mapper.valueToTree(credential.claims());
    }

    /** The DCQL credential format string of a verified presentation. */
    public static String credentialFormat(VerifiedCredential credential) {
        return credential.presentationType() == PresentationType.MDOC
                ? Oid4vpConstants.FORMAT_MSO_MDOC
                : Oid4vpConstants.FORMAT_SD_JWT_VC;
    }
}
