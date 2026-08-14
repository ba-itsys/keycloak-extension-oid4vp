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

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.util.JsonSerialization;

/**
 * Shared context-data conventions between the OID4VP callback processing and the identity
 * provider mappers.
 *
 * <p>The verified credentials are exposed as {@link PresentedCredentials} under
 * {@link #CONTEXT_CREDENTIALS_KEY}, so a mapper resolves its claim path inside its own credential.
 */
public final class Oid4vpMapperUtils {

    public static final String CONTEXT_CREDENTIALS_KEY = "OID4VP_CREDENTIALS";
    public static final String CONTEXT_ISSUER_KEY = "oid4vp_issuer";
    public static final String CONTEXT_SUBJECT_KEY = "oid4vp_subject";

    /** Set when the subject was generated because the subject credential was not presented. */
    public static final String CONTEXT_GENERATED_SUBJECT_KEY = "oid4vp_generated_subject";

    private Oid4vpMapperUtils() {}

    /** The credentials of the verified presentation, or null when the context carries none. */
    public static PresentedCredentials presentedCredentials(BrokeredIdentityContext context) {
        Object credentials = context.getContextData().get(CONTEXT_CREDENTIALS_KEY);
        if (credentials == null) {
            return null;
        }
        if (credentials instanceof PresentedCredentials presented) {
            return presented;
        }
        // A context restored from the authentication session may carry the value untyped.
        return JsonSerialization.mapper.convertValue(credentials, PresentedCredentials.class);
    }
}
