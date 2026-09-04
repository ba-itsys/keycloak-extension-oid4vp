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

import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Indexes the request context by the OAuth {@code state} in Keycloak's
 * {@link SingleUseObjectProvider}. The state is allocated when the login page is rendered and
 * everything that follows carries it: the {@code request_uri} path, the signed request object, the
 * wallet's {@code direct_post}, and the browser's SSE polling and {@code /complete-auth}.
 *
 * <p>The response encryption JWK is created with {@code kid == state}, so an encrypted
 * {@code direct_post.jwt} callback that omits the {@code state} form field still resolves through
 * this index via the cleartext JWE header.
 *
 * <p>The entry is the authoritative liveness check: the flow is live while it exists, and removing
 * it after a successful callback is what blocks replay.
 */
public class Oid4vpRequestObjectStore {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KEY_JSON = "json";
    private static final String KEY_IDP_ALIAS = "idp_alias";
    private final Duration ttl;
    private final String idpAlias;

    /**
     * @param idpAlias the identity provider this store serves. The state index is shared by every
     *     identity provider of the realm. An entry records the alias that created it and resolves
     *     for that alias only, so a presentation posted to another OID4VP identity provider of the
     *     realm cannot complete this one's login under that provider's policy.
     */
    public Oid4vpRequestObjectStore(Duration ttl, String idpAlias) {
        this.ttl = ttl;
        this.idpAlias = idpAlias;
    }

    /**
     * @param dcqlQuery the query snapshot taken when the login page was rendered and served to the
     *     wallet, so that callback enforcement judges the response against the query the wallet
     *     actually answered even when the mapper configuration changes mid-flow
     */
    public record RequestContextEntry(
            String state,
            String rootSessionId,
            String tabId,
            String effectiveClientId,
            String responseUri,
            String flow,
            String nonce,
            String encryptionKeyJson,
            String encryptionJwkThumbprint,
            List<RequestedCredential> requestedCredentials,
            List<CredentialSet> credentialSets,
            String dcqlQuery) {}

    public void storeRequestContext(KeycloakSession session, RequestContextEntry entry) {
        if (entry == null || StringUtil.isBlank(entry.state())) {
            return;
        }
        session.singleUseObjects()
                .put(
                        STATE_INDEX_PREFIX + entry.state(),
                        ttl.toSeconds(),
                        Map.of(KEY_JSON, serializeEntry(entry), KEY_IDP_ALIAS, aliasOrEmpty()));
        LOG.debugf("Stored request context: state=%s", entry.state());
    }

    public RequestContextEntry resolveByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return null;
        Map<String, String> entry = session.singleUseObjects().get(STATE_INDEX_PREFIX + state);
        if (entry == null) return null;
        if (!aliasOrEmpty().equals(entry.get(KEY_IDP_ALIAS))) {
            LOG.warnf(
                    "Request context for state=%s belongs to identity provider '%s', not '%s'",
                    state, entry.get(KEY_IDP_ALIAS), idpAlias);
            return null;
        }
        return deserializeEntry(entry.get(KEY_JSON), RequestContextEntry.class);
    }

    private String aliasOrEmpty() {
        return idpAlias != null ? idpAlias : "";
    }

    public void removeRequestContext(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return;
        session.singleUseObjects().remove(STATE_INDEX_PREFIX + state);
    }

    /** Computes the RFC 7638 SHA-256 JWK thumbprint of the public part of an EC JWK. */
    public static String computeEncryptionJwkThumbprint(String jwkJson) {
        try {
            return Oid4vpJwk.computeThumbprint(jwkJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to compute JWK thumbprint", e);
        }
    }

    private static String serializeEntry(Object entry) {
        try {
            return JsonSerialization.writeValueAsString(entry);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize request-object store entry", e);
        }
    }

    private static <T> T deserializeEntry(String value, Class<T> type) {
        if (StringUtil.isBlank(value)) {
            throw new IllegalStateException("Missing serialized request-object store entry");
        }
        try {
            return JsonSerialization.readValue(value, type);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize request-object store entry", e);
        }
    }
}
