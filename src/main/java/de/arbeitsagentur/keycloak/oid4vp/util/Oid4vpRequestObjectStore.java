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

import com.nimbusds.jose.jwk.ECKey;
import java.time.Duration;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.utils.StringUtil;

/**
 * Stores three types of session lookup indexes in Keycloak's {@link SingleUseObjectProvider}:
 *
 * <ul>
 *   <li><b>Request handle → session</b>: Maps a random UUID (used in the request_uri path) to the
 *       authentication session. Validated when the wallet fetches the request object on demand.
 *   <li><b>State → session</b>: Maps the OAuth state parameter to the authentication session.
 *       Used to recover the session in cross-device and direct_post flows where no session cookie
 *       is available.
 *   <li><b>KID → encryption key</b>: Maps the JWE key ID to the ephemeral encryption key and
 *       associated state. Used to decrypt wallet responses in direct_post.jwt flows when the state
 *       parameter is absent from the response.
 * </ul>
 *
 * <p>All entries expire after the configured TTL (typically the Keycloak login timeout).
 */
public class Oid4vpRequestObjectStore {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final String REQUEST_HANDLE_PREFIX = "oid4vp_request_handle:";
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KID_INDEX_PREFIX = "oid4vp_kid:";

    private final Duration ttl;

    public Oid4vpRequestObjectStore(Duration ttl) {
        this.ttl = ttl;
    }

    public record RequestHandleEntry(String rootSessionId, String tabId) {}

    public record StateEntry(String rootSessionId, String tabId) {}

    public record KidEntry(String encryptionKeyJson, String state) {}

    public void storeRequestHandle(KeycloakSession session, String requestHandle, String rootSessionId, String tabId) {
        long lifespanSeconds = ttl.toSeconds();
        session.singleUseObjects()
                .put(
                        REQUEST_HANDLE_PREFIX + requestHandle,
                        lifespanSeconds,
                        Map.of("rootSessionId", rootSessionId, "tabId", tabId));
        LOG.debugf("Stored request handle: handle=%s, rootSessionId=%s", requestHandle, rootSessionId);
    }

    public void storeStateIndex(KeycloakSession session, String state, String rootSessionId, String tabId) {
        if (StringUtil.isBlank(state)) return;
        session.singleUseObjects()
                .put(
                        STATE_INDEX_PREFIX + state,
                        ttl.toSeconds(),
                        Map.of("rootSessionId", rootSessionId, "tabId", tabId));
    }

    public void storeKidIndex(KeycloakSession session, String kid, String encryptionKeyJson, String state) {
        if (StringUtil.isBlank(kid) || encryptionKeyJson == null) return;
        session.singleUseObjects()
                .put(
                        KID_INDEX_PREFIX + kid,
                        ttl.toSeconds(),
                        Map.of("encryptionKeyJson", encryptionKeyJson, "state", state));
    }

    public RequestHandleEntry resolveRequestHandle(KeycloakSession session, String requestHandle) {
        if (StringUtil.isBlank(requestHandle)) return null;
        Map<String, String> entry = session.singleUseObjects().get(REQUEST_HANDLE_PREFIX + requestHandle);
        if (entry == null) return null;
        return new RequestHandleEntry(entry.get("rootSessionId"), entry.get("tabId"));
    }

    public StateEntry resolveByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return null;
        Map<String, String> entry = session.singleUseObjects().get(STATE_INDEX_PREFIX + state);
        if (entry == null) return null;
        return new StateEntry(entry.get("rootSessionId"), entry.get("tabId"));
    }

    public KidEntry resolveByKid(KeycloakSession session, String kid) {
        if (StringUtil.isBlank(kid)) return null;
        Map<String, String> entry = session.singleUseObjects().get(KID_INDEX_PREFIX + kid);
        if (entry == null) return null;
        return new KidEntry(entry.get("encryptionKeyJson"), entry.get("state"));
    }

    public void removeByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) return;
        SingleUseObjectProvider store = session.singleUseObjects();
        store.remove(STATE_INDEX_PREFIX + state);
    }

    public static String extractKidFromJwk(String jwkJson) {
        try {
            return ECKey.parse(jwkJson).getKeyID();
        } catch (Exception e) {
            return null;
        }
    }
}
