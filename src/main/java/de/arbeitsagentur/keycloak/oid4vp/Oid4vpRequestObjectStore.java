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

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.utils.StringUtil;

public class Oid4vpRequestObjectStore {

    private static final Logger LOG = Logger.getLogger(Oid4vpRequestObjectStore.class);
    private static final String KEY_PREFIX = "oid4vp_request:";
    private static final String STATE_INDEX_PREFIX = "oid4vp_state:";
    private static final String KID_INDEX_PREFIX = "oid4vp_kid:";

    private static final String KEY_REQUEST_OBJECT_JWT = "requestObjectJwt";
    private static final String KEY_ENCRYPTION_KEY_JSON = "encryptionKeyJson";
    private static final String KEY_STATE = "state";
    private static final String KEY_NONCE = "nonce";
    private static final String KEY_ROOT_SESSION_ID = "rootSessionId";
    private static final String KEY_CLIENT_ID = "clientId";
    private static final String KEY_REBUILD_EFFECTIVE_CLIENT_ID = "rebuild.effectiveClientId";
    private static final String KEY_REBUILD_CLIENT_ID_SCHEME = "rebuild.clientIdScheme";
    private static final String KEY_REBUILD_RESPONSE_URI = "rebuild.responseUri";
    private static final String KEY_REBUILD_DCQL_QUERY = "rebuild.dcqlQuery";
    private static final String KEY_REBUILD_X509_CERT_PEM = "rebuild.x509CertPem";
    private static final String KEY_REBUILD_X509_SIGNING_KEY_JWK = "rebuild.x509SigningKeyJwk";
    private static final String KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON = "rebuild.encryptionPublicKeyJson";
    private static final String KEY_REBUILD_VERIFIER_INFO = "rebuild.verifierInfo";

    private final Duration ttl;

    public Oid4vpRequestObjectStore(Duration ttl) {
        this.ttl = ttl;
    }

    public String store(
            KeycloakSession session,
            String requestObjectJwt,
            String encryptionKeyJson,
            String state,
            String nonce,
            String rootSessionId,
            String clientId,
            RebuildParams rebuildParams,
            boolean skipIndexes) {
        SingleUseObjectProvider store = session.singleUseObjects();
        String id = UUID.randomUUID().toString();
        long lifespanSeconds = ttl.toSeconds();

        Map<String, String> notes = new HashMap<>();
        putIfNotNull(notes, KEY_REQUEST_OBJECT_JWT, requestObjectJwt);
        putIfNotNull(notes, KEY_ENCRYPTION_KEY_JSON, encryptionKeyJson);
        putIfNotNull(notes, KEY_STATE, state);
        putIfNotNull(notes, KEY_NONCE, nonce);
        putIfNotNull(notes, KEY_ROOT_SESSION_ID, rootSessionId);
        putIfNotNull(notes, KEY_CLIENT_ID, clientId);

        if (rebuildParams != null) {
            putIfNotNull(notes, KEY_REBUILD_EFFECTIVE_CLIENT_ID, rebuildParams.effectiveClientId());
            putIfNotNull(notes, KEY_REBUILD_CLIENT_ID_SCHEME, rebuildParams.clientIdScheme());
            putIfNotNull(notes, KEY_REBUILD_RESPONSE_URI, rebuildParams.responseUri());
            putIfNotNull(notes, KEY_REBUILD_DCQL_QUERY, rebuildParams.dcqlQuery());
            putIfNotNull(notes, KEY_REBUILD_X509_CERT_PEM, rebuildParams.x509CertPem());
            putIfNotNull(notes, KEY_REBUILD_X509_SIGNING_KEY_JWK, rebuildParams.x509SigningKeyJwk());
            putIfNotNull(notes, KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON, rebuildParams.encryptionPublicKeyJson());
            putIfNotNull(notes, KEY_REBUILD_VERIFIER_INFO, rebuildParams.verifierInfo());
        }

        store.put(KEY_PREFIX + id, lifespanSeconds, notes);

        if (!skipIndexes && StringUtil.isNotBlank(state)) {
            store.put(STATE_INDEX_PREFIX + state, lifespanSeconds, Map.of("id", id));
        }
        // Always store kid index: each request object has a unique encryption key,
        // so the kid index must exist for encrypted wallet responses (e.g. mDoc JWE)
        if (encryptionKeyJson != null) {
            String kid = extractKidFromJwk(encryptionKeyJson);
            if (kid != null) {
                store.put(KID_INDEX_PREFIX + kid, lifespanSeconds, Map.of("id", id));
            }
        }

        LOG.debugf("Stored request object: id=%s, state=%s", id, state);
        return id;
    }

    public StoredRequestObject resolveByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) {
            return null;
        }
        Map<String, String> indexEntry = session.singleUseObjects().get(STATE_INDEX_PREFIX + state);
        if (indexEntry == null) {
            return null;
        }
        String id = indexEntry.get("id");
        return id != null ? resolve(session, id) : null;
    }

    public StoredRequestObject resolveByKid(KeycloakSession session, String kid) {
        if (StringUtil.isBlank(kid)) {
            return null;
        }
        Map<String, String> indexEntry = session.singleUseObjects().get(KID_INDEX_PREFIX + kid);
        if (indexEntry == null) {
            return null;
        }
        String id = indexEntry.get("id");
        return id != null ? resolve(session, id) : null;
    }

    public StoredRequestObject resolve(KeycloakSession session, String id) {
        if (StringUtil.isBlank(id)) {
            return null;
        }
        Map<String, String> notes = session.singleUseObjects().get(KEY_PREFIX + id);
        return notes != null ? deserialize(notes) : null;
    }

    public void remove(KeycloakSession session, String id) {
        if (StringUtil.isBlank(id)) {
            return;
        }
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> notes = store.get(KEY_PREFIX + id);
        if (notes != null) {
            String state = notes.get(KEY_STATE);
            if (StringUtil.isNotBlank(state)) {
                store.remove(STATE_INDEX_PREFIX + state);
            }
            String encKeyJson = notes.get(KEY_ENCRYPTION_KEY_JSON);
            if (encKeyJson != null) {
                String kid = extractKidFromJwk(encKeyJson);
                if (kid != null) {
                    store.remove(KID_INDEX_PREFIX + kid);
                }
            }
        }
        store.remove(KEY_PREFIX + id);
    }

    public void removeByState(KeycloakSession session, String state) {
        if (StringUtil.isBlank(state)) {
            return;
        }
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> indexEntry = store.get(STATE_INDEX_PREFIX + state);
        if (indexEntry != null) {
            String id = indexEntry.get("id");
            if (StringUtil.isNotBlank(id)) {
                Map<String, String> notes = store.get(KEY_PREFIX + id);
                if (notes != null) {
                    String encKeyJson = notes.get(KEY_ENCRYPTION_KEY_JSON);
                    if (encKeyJson != null) {
                        String kid = extractKidFromJwk(encKeyJson);
                        if (kid != null) {
                            store.remove(KID_INDEX_PREFIX + kid);
                        }
                    }
                }
                store.remove(KEY_PREFIX + id);
            }
        }
        store.remove(STATE_INDEX_PREFIX + state);
    }

    private static String extractKidFromJwk(String jwkJson) {
        try {
            return com.nimbusds.jose.jwk.ECKey.parse(jwkJson).getKeyID();
        } catch (Exception e) {
            return null;
        }
    }

    private void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    private StoredRequestObject deserialize(Map<String, String> notes) {
        RebuildParams rebuildParams = null;
        String effectiveClientId = notes.get(KEY_REBUILD_EFFECTIVE_CLIENT_ID);
        if (effectiveClientId != null) {
            rebuildParams = new RebuildParams(
                    effectiveClientId,
                    notes.get(KEY_REBUILD_CLIENT_ID_SCHEME),
                    notes.get(KEY_REBUILD_RESPONSE_URI),
                    notes.get(KEY_REBUILD_DCQL_QUERY),
                    notes.get(KEY_REBUILD_X509_CERT_PEM),
                    notes.get(KEY_REBUILD_X509_SIGNING_KEY_JWK),
                    notes.get(KEY_REBUILD_ENCRYPTION_PUBLIC_KEY_JSON),
                    notes.get(KEY_REBUILD_VERIFIER_INFO));
        }

        return new StoredRequestObject(
                notes.get(KEY_REQUEST_OBJECT_JWT),
                notes.get(KEY_ENCRYPTION_KEY_JSON),
                notes.get(KEY_STATE),
                notes.get(KEY_NONCE),
                notes.get(KEY_ROOT_SESSION_ID),
                notes.get(KEY_CLIENT_ID),
                rebuildParams);
    }

    public record RebuildParams(
            String effectiveClientId,
            String clientIdScheme,
            String responseUri,
            String dcqlQuery,
            String x509CertPem,
            String x509SigningKeyJwk,
            String encryptionPublicKeyJson,
            String verifierInfo) {}

    public record StoredRequestObject(
            String requestObjectJwt,
            String encryptionKeyJson,
            String state,
            String nonce,
            String rootSessionId,
            String clientId,
            RebuildParams rebuildParams) {}
}
