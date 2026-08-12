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
 * Stores a single state → request context index in Keycloak's {@link SingleUseObjectProvider}:
 * the OAuth {@code state} value maps to a serialized {@link RequestContextEntry}. The same
 * {@code state} is allocated when the login page is rendered, carried in the {@code request_uri}
 * path, advertised inside the signed request object, echoed by the wallet in its
 * {@code direct_post}, and used by the browser for SSE polling and {@code /complete-auth}.
 *
 * <p>The response-encryption JWK is created with {@code kid == state}, so an encrypted
 * {@code direct_post.jwt} callback that omits the {@code state} form field still resolves through
 * this index via the cleartext JWE header kid.
 *
 * <p>The state entry is the authoritative liveness check: while it exists the flow is live, and
 * removing it after a successful callback blocks replay.
 *
 * <p>All entries expire after the configured TTL (typically the Keycloak login timeout).
 */
public class Oid4vpRequestObjectStore {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KEY_JSON = "json";
    private final Duration ttl;

    public Oid4vpRequestObjectStore(Duration ttl) {
        this.ttl = ttl;
    }

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
            List<String> configuredCredentialTypes,
            List<RequestedCredential> requestedCredentials) {}

    // Stores a state → request context mapping. Called when the login page is rendered.
    public void storeRequestContext(KeycloakSession session, RequestContextEntry entry) {
        if (entry == null || StringUtil.isBlank(entry.state())) {
            return;
        }
        session.singleUseObjects()
                .put(STATE_INDEX_PREFIX + entry.state(), ttl.toSeconds(), Map.of(KEY_JSON, serializeEntry(entry)));
        LOG.debugf("Stored request context: state=%s", entry.state());
    }

    public RequestContextEntry resolveByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return null;
        Map<String, String> entry = session.singleUseObjects().get(STATE_INDEX_PREFIX + state);
        if (entry == null) return null;
        return deserializeEntry(entry.get(KEY_JSON), RequestContextEntry.class);
    }

    public void removeRequestContext(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return;
        session.singleUseObjects().remove(STATE_INDEX_PREFIX + state);
    }

    // Computes the RFC 7638 SHA-256 JWK thumbprint for the public part of an EC JWK.
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
