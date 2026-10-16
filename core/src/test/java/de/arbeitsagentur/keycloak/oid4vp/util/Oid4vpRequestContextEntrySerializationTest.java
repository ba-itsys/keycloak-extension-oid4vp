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

import static org.assertj.core.api.Assertions.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential.RequestedClaim;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.OID4VCConstants;
import org.keycloak.broker.oid4vp.EphemeralKey;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/**
 * The request context is stored as JSON between rendering the login page and processing the
 * wallet's response. The credential set model the callback enforces has to survive the round
 * trip. A credential set that does not deserialize would only surface as a failed login.
 */
class Oid4vpRequestContextEntrySerializationTest {

    @Test
    void requestUriDeadline_expiresRetrievalAtDeadline() {
        Oid4vpRequestObjectStore.RequestContextEntry entry = new Oid4vpRequestObjectStore.RequestContextEntry(
                "state",
                "root",
                "tab",
                "client",
                "https://example.com/callback",
                "cross_device",
                "nonce",
                null,
                List.of(),
                List.of(),
                "{}",
                300);

        assertThat(entry.isRequestUriExpired(299)).isFalse();
        assertThat(entry.isRequestUriExpired(300)).isTrue();
        assertThat(entry.isRequestUriExpired(301)).isTrue();
    }

    @Test
    void requestContextEntry_survivesJsonRoundTrip() throws Exception {
        Oid4vpRequestObjectStore.RequestContextEntry entry = new Oid4vpRequestObjectStore.RequestContextEntry(
                "state",
                "root-session",
                "tab-1",
                "test-client",
                "https://example.com/callback",
                "same_device",
                "nonce",
                null,
                List.of(new RequestedCredential(
                        "pid",
                        OID4VCConstants.FORMAT_SD_JWT_VC,
                        List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1"),
                        List.of(new RequestedClaim(null, "sub"), new RequestedClaim(null, "given_name")),
                        List.of(List.of(0, 1), List.of(0)))),
                List.of(
                        new CredentialSet(List.of(List.of("pid", "mdl"), List.of("pid")), true, "Login"),
                        new CredentialSet(List.of(List.of("diploma")), false, null)),
                "{\"credentials\":[]}",
                1_800_000_000L);

        String json = JsonSerialization.writeValueAsString(entry);
        Oid4vpRequestObjectStore.RequestContextEntry restored =
                JsonSerialization.readValue(json, Oid4vpRequestObjectStore.RequestContextEntry.class);

        assertThat(restored).isEqualTo(entry);
        assertThat(restored.credentialSets().get(0).options()).containsExactly(List.of("pid", "mdl"), List.of("pid"));
        assertThat(restored.credentialSets().get(0).purpose()).isEqualTo("Login");
        assertThat(restored.credentialSets().get(1).required()).isFalse();
        assertThat(restored.requestedCredentials().get(0).id()).isEqualTo("pid");
        assertThat(restored.requestedCredentials().get(0).types())
                .containsExactly("urn:eudi:pid:1", "urn:eudi:pid:de:1");
        assertThat(restored.requestedCredentials().get(0).claimSets()).containsExactly(List.of(0, 1), List.of(0));
    }

    @Test
    void responseEncryptionKey_survivesJsonRoundTrip() throws Exception {
        CryptoIntegration.init(Oid4vpRequestContextEntrySerializationTest.class.getClassLoader());
        EphemeralKey key = EphemeralKey.generate("state");
        Oid4vpRequestObjectStore.RequestContextEntry entry = new Oid4vpRequestObjectStore.RequestContextEntry(
                "state",
                "root",
                "tab",
                "client",
                "https://example.com/callback",
                "same_device",
                "nonce",
                key,
                List.of(),
                List.of(),
                "{}",
                0);

        EphemeralKey restored = JsonSerialization.readValue(
                        JsonSerialization.writeValueAsString(entry), Oid4vpRequestObjectStore.RequestContextEntry.class)
                .encryptionKey();

        assertThat(restored.kid()).isEqualTo("state");
        assertThat(restored.privateKey()).isEqualTo(key.privateKey());
        assertThat(JWKSUtils.computeThumbprint(restored.publicJwk()))
                .isEqualTo(JWKSUtils.computeThumbprint(key.publicJwk()));
    }

    @Test
    void entryWithFieldsOfAnEarlierVersion_stillDeserializes() throws Exception {
        String json = """
                {"state":"state","nonce":"nonce","encryptionKeyJson":"{}","encryptionJwkThumbprint":"abc",\
                "requestedCredentials":[],"credentialSets":[],"requestUriExpiresAtEpochSeconds":0}""";

        Oid4vpRequestObjectStore.RequestContextEntry restored =
                JsonSerialization.readValue(json, Oid4vpRequestObjectStore.RequestContextEntry.class);

        assertThat(restored.state()).isEqualTo("state");
        assertThat(restored.encryptionKey()).isNull();
    }
}
