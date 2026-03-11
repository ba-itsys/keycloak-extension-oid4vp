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
                .put(anyString(), anyLong(), org.mockito.ArgumentMatchers.<Map<String, String>>any());
        when(singleUseObjects.get(anyString())).thenAnswer(invocation -> entries.get(invocation.getArgument(0)));
        when(singleUseObjects.remove(anyString())).thenAnswer(invocation -> entries.remove(invocation.getArgument(0)));

        store = new Oid4vpRequestObjectStore(Duration.ofMinutes(5));
    }

    @Test
    void resolveByStateAndKid_returnsRequestContextBoundToFlowHandle() {
        Oid4vpRequestObjectStore.FlowContextEntry flowContext = new Oid4vpRequestObjectStore.FlowContextEntry(
                "root-session", "tab-1", "client-1", "https://example.com/endpoint");
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-1",
                "client-1",
                "https://example.com/endpoint",
                "nonce-1",
                KEY_JSON_1,
                "thumbprint-1");

        store.storeFlowHandle(session, "handle-1", flowContext);
        store.storeRequestContext(session, requestContext);
        store.storeKidIndex(session, "kid-1", requestContext.state());

        assertThat(store.resolveFlowHandle(session, "handle-1")).isEqualTo(flowContext);
        assertThat(store.resolveByState(session, requestContext.state())).isEqualTo(requestContext);
        assertThat(store.resolveByKid(session, "kid-1")).isEqualTo(requestContext);
    }

    @Test
    void removeFlowHandle_invalidatesAllOutstandingRequestContextsForThatFlow() {
        Oid4vpRequestObjectStore.FlowContextEntry flowContext = new Oid4vpRequestObjectStore.FlowContextEntry(
                "root-session", "tab-1", "client-1", "https://example.com/endpoint");
        Oid4vpRequestObjectStore.RequestContextEntry firstRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-1",
                "client-1",
                "https://example.com/endpoint",
                "nonce-1",
                KEY_JSON_1,
                "thumbprint-1");
        Oid4vpRequestObjectStore.RequestContextEntry secondRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-2",
                "client-1",
                "https://example.com/endpoint",
                "nonce-2",
                KEY_JSON_2,
                "thumbprint-2");

        store.storeFlowHandle(session, "handle-1", flowContext);
        store.storeRequestContext(session, firstRequest);
        store.storeRequestContext(session, secondRequest);
        store.storeKidIndex(session, "kid-1", firstRequest.state());
        store.storeKidIndex(session, "kid-2", secondRequest.state());

        store.removeFlowHandle(session, "handle-1");

        assertThat(store.resolveFlowHandle(session, "handle-1")).isNull();
        assertThat(store.resolveByState(session, firstRequest.state())).isNull();
        assertThat(store.resolveByState(session, secondRequest.state())).isNull();
        assertThat(store.resolveByKid(session, "kid-1")).isNull();
        assertThat(store.resolveByKid(session, "kid-2")).isNull();
        assertThat(entries)
                .doesNotContainKeys(
                        "oid4vp_request_handle:handle-1",
                        "oid4vp_state:state-1",
                        "oid4vp_state:state-2",
                        "oid4vp_kid:kid-1",
                        "oid4vp_kid:kid-2");
    }

    @Test
    void removeRequestContext_cleansOnlyTargetedStateAndKid() {
        Oid4vpRequestObjectStore.FlowContextEntry flowContext = new Oid4vpRequestObjectStore.FlowContextEntry(
                "root-session", "tab-1", "client-1", "https://example.com/endpoint");
        Oid4vpRequestObjectStore.RequestContextEntry firstRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-1",
                "client-1",
                "https://example.com/endpoint",
                "nonce-1",
                KEY_JSON_1,
                "thumbprint-1");
        Oid4vpRequestObjectStore.RequestContextEntry secondRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-2",
                "client-1",
                "https://example.com/endpoint",
                "nonce-2",
                KEY_JSON_2,
                "thumbprint-2");

        store.storeFlowHandle(session, "handle-1", flowContext);
        store.storeRequestContext(session, firstRequest);
        store.storeRequestContext(session, secondRequest);
        store.storeKidIndex(session, "kid-1", firstRequest.state());
        store.storeKidIndex(session, "kid-2", secondRequest.state());

        store.removeRequestContext(session, firstRequest.state());

        assertThat(store.resolveByState(session, firstRequest.state())).isNull();
        assertThat(store.resolveByKid(session, "kid-1")).isNull();
        assertThat(store.resolveByState(session, secondRequest.state())).isEqualTo(secondRequest);
        assertThat(store.resolveByKid(session, "kid-2")).isEqualTo(secondRequest);
        assertThat(entries).doesNotContainKeys("oid4vp_state:state-1", "oid4vp_kid:kid-1");
        assertThat(entries).containsKeys("oid4vp_request_handle:handle-1", "oid4vp_state:state-2", "oid4vp_kid:kid-2");
    }

    @Test
    void resolveByStateAndKid_lazilyCleansOrphanedEntriesWhenFlowHandleIsGone() {
        Oid4vpRequestObjectStore.RequestContextEntry requestContext = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-missing",
                "root-session",
                "tab-1",
                "state-orphan",
                "client-1",
                "https://example.com/endpoint",
                "nonce-1",
                KEY_JSON_1,
                "thumbprint-1");

        store.storeRequestContext(session, requestContext);
        store.storeKidIndex(session, "kid-1", requestContext.state());

        assertThat(store.resolveByState(session, requestContext.state())).isNull();
        assertThat(store.resolveByKid(session, "kid-1")).isNull();
        assertThat(entries).doesNotContainKeys("oid4vp_state:state-orphan", "oid4vp_kid:kid-1");
    }

    @Test
    void removeFlowHandle_leavesNoValidSiblingStatesEvenIfTheyWereNotExplicitlyTracked() {
        Oid4vpRequestObjectStore.FlowContextEntry flowContext = new Oid4vpRequestObjectStore.FlowContextEntry(
                "root-session", "tab-1", "client-1", "https://example.com/endpoint");
        Oid4vpRequestObjectStore.RequestContextEntry firstRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-1",
                "client-1",
                "https://example.com/endpoint",
                "nonce-1",
                KEY_JSON_1,
                "thumbprint-1");
        Oid4vpRequestObjectStore.RequestContextEntry secondRequest = new Oid4vpRequestObjectStore.RequestContextEntry(
                "handle-1",
                "root-session",
                "tab-1",
                "state-2",
                "client-1",
                "https://example.com/endpoint",
                "nonce-2",
                KEY_JSON_2,
                "thumbprint-2");

        store.storeFlowHandle(session, "handle-1", flowContext);
        store.storeRequestContext(session, firstRequest);
        store.storeRequestContext(session, secondRequest);
        store.storeKidIndex(session, "kid-1", firstRequest.state());
        store.storeKidIndex(session, "kid-2", secondRequest.state());

        store.removeFlowHandle(session, "handle-1");

        assertThat(entries)
                .containsKeys("oid4vp_state:state-1", "oid4vp_state:state-2", "oid4vp_kid:kid-1", "oid4vp_kid:kid-2");
        assertThat(store.resolveByState(session, firstRequest.state())).isNull();
        assertThat(store.resolveByKid(session, "kid-2")).isNull();
        assertThat(entries)
                .doesNotContainKeys(
                        "oid4vp_state:state-1", "oid4vp_state:state-2", "oid4vp_kid:kid-1", "oid4vp_kid:kid-2");
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
