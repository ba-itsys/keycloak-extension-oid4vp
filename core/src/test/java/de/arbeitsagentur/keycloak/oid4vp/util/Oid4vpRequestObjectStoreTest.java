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

    private static final String KEY_JSON_1 = createKey("state-1");
    private static final String KEY_JSON_2 = createKey("state-2");

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
    void resolveByState_returnsStoredRequestContext() {
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);

        store.storeRequestContext(session, requestContext);

        assertThat(store.resolveByState(session, "state-1")).isEqualTo(requestContext);
    }

    @Test
    void resolveByState_withEncryptionKeyKid_returnsRequestContext() {
        // The response-encryption JWK is minted with kid == state, so the JWE header kid of an
        // encrypted callback resolves the request context through the plain state index.
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);

        store.storeRequestContext(session, requestContext);
        String kid = Oid4vpSigningKeyParser.extractKid(requestContext.encryptionKeyJson());

        assertThat(kid).isEqualTo("state-1");
        assertThat(store.resolveByState(session, kid)).isEqualTo(requestContext);
    }

    @Test
    void removeRequestContext_removesStateEntry() {
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestContext("state-1", "nonce-1", KEY_JSON_1);

        store.storeRequestContext(session, requestContext);

        store.removeRequestContext(session, "state-1");

        assertThat(store.resolveByState(session, "state-1")).isNull();
        assertThat(entries).doesNotContainKey("oid4vp_state:state-1");
    }

    @Test
    void removeRequestContext_cleansOnlyTargetedState() {
        Oid4vpRequestObjectStore.RequestContextEntry firstRequest = requestContext("state-1", "nonce-1", KEY_JSON_1);
        Oid4vpRequestObjectStore.RequestContextEntry secondRequest = requestContext("state-2", "nonce-2", KEY_JSON_2);

        store.storeRequestContext(session, firstRequest);
        store.storeRequestContext(session, secondRequest);

        store.removeRequestContext(session, "state-1");

        assertThat(store.resolveByState(session, "state-1")).isNull();
        assertThat(store.resolveByState(session, "state-2")).isEqualTo(secondRequest);
        assertThat(entries).doesNotContainKey("oid4vp_state:state-1");
        assertThat(entries).containsKey("oid4vp_state:state-2");
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
                List.of(),
                null);
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
