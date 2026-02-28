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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import java.util.zip.Deflater;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class StatusListVerifierTest {

    private final StatusListVerifier verifier = new StatusListVerifier();

    @AfterEach
    void clearCaches() {
        StatusListVerifier.clearCache();
    }

    @Test
    void constructorWithMaxCacheTtl_acceptsZero() {
        StatusListVerifier v = new StatusListVerifier(null, null, Duration.ZERO);
        // Should not throw; verifier is functional for non-HTTP operations
        v.checkRevocationStatus(Map.of("given_name", "Alice"));
    }

    @Test
    void constructorWithMaxCacheTtl_acceptsNull() {
        StatusListVerifier v = new StatusListVerifier(null, null, null);
        v.checkRevocationStatus(Map.of());
    }

    @Test
    void extractsStatusReferenceFromValidPayload() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://issuer.example/status/abc", "idx", 42)));

        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status/abc");
        assertThat(ref.idx()).isEqualTo(42);
    }

    @Test
    void returnsNullForMissingStatusClaim() {
        assertThat(verifier.extractStatusReference(Map.of())).isNull();
        assertThat(verifier.extractStatusReference(Map.of("status", "not-a-map")))
                .isNull();
        assertThat(verifier.extractStatusReference(null)).isNull();
    }

    @Test
    void returnsNullForMalformedStatusList() {
        Map<String, Object> payload = Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com")));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void returnsNullWhenStatusListIsMissing() {
        Map<String, Object> payload = Map.of("status", Map.of("other_field", "value"));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void getStatusAtIndexReturnsZeroForValidEntry() {
        byte[] bits = new byte[] {0x00, 0x00};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 7, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 15, 1)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexDetectsRevokedBit() {
        byte[] bits = new byte[] {0x02};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 1)).isEqualTo(0);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 1)).isEqualTo(1);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 2, 1)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexSupportsMultiBit() {
        byte[] bits = new byte[] {(byte) 0x0B};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 2)).isEqualTo(3);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 2)).isEqualTo(2);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 2, 2)).isEqualTo(0);
    }

    @Test
    void getStatusAtIndexThrowsForOutOfRange() {
        byte[] bits = new byte[] {0x00};
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(bits, 100, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("out of range");
    }

    @Test
    void inflateRoundTripRawDeflate() throws Exception {
        byte[] original = new byte[] {0x00, 0x01, 0x02, (byte) 0xFF, 0x00, 0x55};

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(original);
        deflater.finish();
        byte[] compressed = new byte[256];
        int compressedLen = deflater.deflate(compressed);
        deflater.end();

        byte[] trimmed = new byte[compressedLen];
        System.arraycopy(compressed, 0, trimmed, 0, compressedLen);

        byte[] inflated = StatusListVerifier.inflate(trimmed);
        assertThat(inflated).isEqualTo(original);
    }

    @Test
    void inflateRoundTripZlib() throws Exception {
        byte[] original = new byte[] {0x00, 0x01, 0x02, (byte) 0xFF, 0x00, 0x55};

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, false);
        deflater.setInput(original);
        deflater.finish();
        byte[] compressed = new byte[256];
        int compressedLen = deflater.deflate(compressed);
        deflater.end();

        byte[] trimmed = new byte[compressedLen];
        System.arraycopy(compressed, 0, trimmed, 0, compressedLen);

        byte[] inflated = StatusListVerifier.inflate(trimmed);
        assertThat(inflated).isEqualTo(original);
    }

    @Test
    void checkRevocationStatusPassesWhenNoStatusClaim() {
        verifier.checkRevocationStatus(Map.of("given_name", "Alice"));
        verifier.checkRevocationStatus(Map.of());
    }

    @Test
    void extractsStatusReferenceWithLongIdx() {
        Map<String, Object> payload = Map.of(
                "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status/mdoc", "idx", 53L)));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.idx()).isEqualTo(53);
    }

    @Test
    void extractsStatusReferenceFromMdocNamespacedKey() {
        Map<String, Object> claims = Map.of(
                "eu.europa.ec.eudi.pid.1/family_name",
                "Smith",
                "eu.europa.ec.eudi.pid.1/status",
                Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 7)));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(claims);
        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status");
        assertThat(ref.idx()).isEqualTo(7);
    }
}
