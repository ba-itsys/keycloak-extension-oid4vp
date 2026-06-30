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
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Stores two lookup indexes in Keycloak's {@link SingleUseObjectProvider}:
 *
 * <ul>
 *   <li><b>State → request context</b>: Maps the OAuth {@code state} value to a serialized
 *       {@link RequestContextEntry}. The same {@code state} is allocated when the login page is
 *       rendered, carried in the {@code request_uri} path, advertised inside the signed request
 *       object, echoed by the wallet in its {@code direct_post}, and used by the browser for SSE
 *       polling and {@code /complete-auth}.
 *   <li><b>KID → request context</b>: Maps the HAIP response-encryption JWK key ID directly to the
 *       serialized request context so {@code direct_post.jwt} callbacks can recover the correct
 *       decryption key even when the wallet omits the {@code state} form field and state propagation
 *       across nodes lags slightly.
 * </ul>
 *
 * <p>The state entry is the authoritative liveness check: while it exists the flow is live, and
 * removing it after a successful callback rejects any leftover KID entry and blocks replay.
 *
 * <p>All entries expire after the configured TTL (typically the Keycloak login timeout).
 */
public class Oid4vpRequestObjectStore {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KID_INDEX_PREFIX = "oid4vp_kid:";
    private static final String KEY_JSON = "json";
    private static final String KEY_STATE = "state";
    private static final String KEY_KID = JWK.KEY_ID;
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
            List<String> configuredCredentialTypes) {}

    // Stores a state → request context mapping. Called when the login page is rendered.
    public void storeRequestContext(KeycloakSession session, RequestContextEntry entry) {
        if (entry == null || StringUtil.isBlank(entry.state())) {
            return;
        }
        session.singleUseObjects()
                .put(
                        STATE_INDEX_PREFIX + entry.state(),
                        ttl.toSeconds(),
                        Map.of(
                                KEY_JSON,
                                serializeEntry(entry),
                                KEY_KID,
                                emptyIfNull(extractKidFromJwk(entry.encryptionKeyJson()))));
        LOG.debugf("Stored request context: state=%s", entry.state());
    }

    // Stores a KID → request context mapping for decrypting direct_post.jwt responses.
    public void storeKidIndex(KeycloakSession session, String kid, RequestContextEntry entry) {
        if (StringUtil.isBlank(kid) || entry == null || StringUtil.isBlank(entry.state())) return;
        session.singleUseObjects()
                .put(
                        KID_INDEX_PREFIX + kid,
                        ttl.toSeconds(),
                        Map.of(KEY_STATE, entry.state(), KEY_JSON, serializeEntry(entry)));
    }

    public RequestContextEntry resolveByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return null;
        Map<String, String> entry = session.singleUseObjects().get(STATE_INDEX_PREFIX + state);
        if (entry == null) return null;
        return deserializeEntry(entry.get(KEY_JSON), RequestContextEntry.class);
    }

    public RequestContextEntry resolveByKid(KeycloakSession session, String kid) {
        if (StringUtil.isBlank(kid)) return null;
        Map<String, String> entry = session.singleUseObjects().get(KID_INDEX_PREFIX + kid);
        if (entry == null) return null;
        // The KID index and the state index are written together and removed together
        // (removeRequestContext clears both), so a live KID entry implies a live request context.
        String serializedRequestContext = blankToNull(entry.get(KEY_JSON));
        if (serializedRequestContext != null) {
            return deserializeEntry(serializedRequestContext, RequestContextEntry.class);
        }
        String state = blankToNull(entry.get(KEY_STATE));
        if (state == null) {
            session.singleUseObjects().remove(KID_INDEX_PREFIX + kid);
            return null;
        }
        return resolveByState(session, state);
    }

    public void removeRequestContext(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return;
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> stateEntry = store.remove(STATE_INDEX_PREFIX + state);
        if (stateEntry == null) return;

        String kid = blankToNull(stateEntry.get(KEY_KID));
        if (kid != null) {
            store.remove(KID_INDEX_PREFIX + kid);
        }
    }

    // Extracts the Key ID from a JWK JSON string, or null if parsing fails.
    public static String extractKidFromJwk(String jwkJson) {
        return Oid4vpSigningKeyParser.extractKid(jwkJson);
    }

    // Computes the RFC 7638 SHA-256 JWK thumbprint for the public part of an EC JWK.
    public static String computeEncryptionJwkThumbprint(String jwkJson) {
        try {
            return Oid4vpJwk.computeThumbprint(jwkJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to compute JWK thumbprint", e);
        }
    }

    private static String emptyIfNull(String value) {
        return value == null ? "" : value;
    }

    private static String blankToNull(String value) {
        return StringUtil.isBlank(value) ? null : value;
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
