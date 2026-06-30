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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

class Oid4vpRequestObjectStoreTest {

    private static final String KEY_JSON_1 = createKey("kid-1");
    private static final String KEY_JSON_2 = createKey("kid-2");

    private final Map<String, Map<String, String>> entries = new HashMap<>();

    private KeycloakSession session;
    private Oid4vpRequestObjectStore store;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        SingleUseObjectProvider singleUseObjects = mock(SingleUseObjectProvider.class);
        when(session.singleUseObjects()).thenReturn(singleUseObjects);

        doAnswer(invocation -> {
                    entries.put(invocation.getArgument(0), invocation.getArgument(2));
                    return null;
                })
                .when(singleUseObjects)
                .put(anyString(), anyLong(), any());
        when(singleUseObjects.get(anyString())).thenAnswer(invocation -> entries.get(invocation.getArgument(0)));
        when(singleUseObjects.remove(anyString())).thenAnswer(invocation -> entries.remove(invocation.getArgument(0)));

        store = new Oid4vpRequestObjectStore(Duration.ofMinutes(5));
    }

    @Test
    void resolveByStateAndKid_returnsStoredRequestContext() {
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);

        store.storeRequestContext(session, requestContext);
        store.storeKidIndex(session, "kid-1", requestContext);

        assertThat(store.resolveByState(session, "state-1")).isEqualTo(requestContext);
        assertThat(store.resolveByKid(session, "kid-1")).isEqualTo(requestContext);
    }

    @Test
    void removeRequestContext_removesStateAndAssociatedKid() {
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);

        store.storeRequestContext(session, requestContext);
        store.storeKidIndex(session, "kid-1", requestContext);

        store.removeRequestContext(session, "state-1");

        assertThat(store.resolveByState(session, "state-1")).isNull();
        assertThat(store.resolveByKid(session, "kid-1")).isNull();
        assertThat(entries).doesNotContainKeys("oid4vp_state:state-1", "oid4vp_kid:kid-1");
    }

    @Test
    void removeRequestContext_cleansOnlyTargetedStateAndKid() {
        Oid4vpRequestObjectStore.RequestContextEntry firstRequest = requestContext("state-1", "nonce-1", KEY_JSON_1);
        Oid4vpRequestObjectStore.RequestContextEntry secondRequest = requestContext("state-2", "nonce-2", KEY_JSON_2);

        store.storeRequestContext(session, firstRequest);
        store.storeRequestContext(session, secondRequest);
        store.storeKidIndex(session, "kid-1", firstRequest);
        store.storeKidIndex(session, "kid-2", secondRequest);

        store.removeRequestContext(session, "state-1");

        assertThat(store.resolveByState(session, "state-1")).isNull();
        assertThat(store.resolveByKid(session, "kid-1")).isNull();
        assertThat(store.resolveByState(session, "state-2")).isEqualTo(secondRequest);
        assertThat(store.resolveByKid(session, "kid-2")).isEqualTo(secondRequest);
        assertThat(entries).doesNotContainKeys("oid4vp_state:state-1", "oid4vp_kid:kid-1");
        assertThat(entries).containsKeys("oid4vp_state:state-2", "oid4vp_kid:kid-2");
    }

    @Test
    void resolveByKid_returnsNullAndCleansWhenKidEntryHasNoContextAndNoState() {
        store.storeRequestContext(session, requestContext("state-1", "nonce-1", KEY_JSON_1));
        // A KID entry that carries neither the serialized context nor a state pointer is unusable.
        entries.put("oid4vp_kid:kid-empty", Map.of());

        assertThat(store.resolveByKid(session, "kid-empty")).isNull();
        assertThat(entries).doesNotContainKey("oid4vp_kid:kid-empty");
    }

    @Test
    void resolveByKid_returnsEmbeddedContextEvenIfStateEntryNotVisibleYet() {
        // A direct_post.jwt callback can land on a node where the state index has not propagated yet.
        // The KID entry embeds the full context, so resolution still succeeds during that lag.
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);
        store.storeKidIndex(session, "kid-1", requestContext);
        // storeRequestContext intentionally not called: the state index is absent (propagation lag).

        assertThat(store.resolveByKid(session, "kid-1")).isEqualTo(requestContext);
    }

    @Test
    void resolveByKid_fallsBackToStatePointerWhenContextNotEmbedded() {
        store.storeRequestContext(session, requestContext("state-1", "nonce-1", KEY_JSON_1));
        // Simulate a legacy KID entry that only points at the state index.
        entries.put("oid4vp_kid:kid-pointer", Map.of("state", "state-1"));

        assertThat(store.resolveByKid(session, "kid-pointer"))
                .isEqualTo(requestContext("state-1", "nonce-1", KEY_JSON_1));
    }

    private static Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String state, String nonce, String encryptionKeyJson) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                "root-session",
                "tab-1",
                "client-1",
                "https://example.com/endpoint",
                "same_device",
                nonce,
                encryptionKeyJson,
                "thumbprint",
                List.of());
    }

    private static String createKey(String kid) {
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
            return key.toJSONString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate test JWK", e);
        }
    }
}
