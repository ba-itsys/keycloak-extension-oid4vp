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

import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.time.Duration;
import java.time.Instant;
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
    void returnsNullForNonNumericStatusIndex() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com", "idx", "abc")));
        assertThat(verifier.extractStatusReference(payload)).isNull();
    }

    @Test
    void extractsStatusReferenceFromStringIndex() {
        Map<String, Object> payload =
                Map.of("status", Map.of("status_list", Map.of("uri", "https://example.com", "idx", "17")));
        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);
        assertThat(ref).isNotNull();
        assertThat(ref.idx()).isEqualTo(17);
    }

    @Test
    void extractsStatusReferenceFromJsonNodeValues() {
        Map<String, Object> payload = Map.of(
                "status",
                Map.of(
                        "status_list",
                        Map.of(
                                "uri", TextNode.valueOf("https://issuer.example/status/abc"),
                                "idx", IntNode.valueOf(42))));

        StatusListVerifier.StatusReference ref = verifier.extractStatusReference(payload);

        assertThat(ref).isNotNull();
        assertThat(ref.uri()).isEqualTo("https://issuer.example/status/abc");
        assertThat(ref.idx()).isEqualTo(42);
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
    void getStatusAtIndexRejectsBitsValueOutsideSpec() {
        byte[] bits = new byte[] {0x00};
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(bits, 0, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one of 1, 2, 4, or 8");
    }

    @Test
    void getStatusAtIndexSupportsEightBitStatuses() {
        byte[] bits = new byte[] {(byte) 0xFE, (byte) 0x7F};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 8)).isEqualTo(254);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 8)).isEqualTo(127);
    }

    @Test
    void getStatusAtIndexSupportsFourBitStatuses() {
        byte[] bits = new byte[] {(byte) 0xAB};
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 0, 4)).isEqualTo(11);
        assertThat(StatusListVerifier.getStatusAtIndex(bits, 1, 4)).isEqualTo(10);
    }

    @Test
    void getStatusAtIndexRejectsEmptyStatusList() {
        assertThatThrownBy(() -> StatusListVerifier.getStatusAtIndex(new byte[0], 0, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty status list");
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
    void checkRevocationStatusThrowsWhenCredentialIsRevoked() {
        StatusListVerifier revokedVerifier = new StatusListVerifier() {
            @Override
            DecodedStatusList fetchAndDecodeStatusList(String uri) {
                return new DecodedStatusList(new byte[] {0x01}, 1);
            }
        };

        assertThatThrownBy(() -> revokedVerifier.checkRevocationStatus(Map.of(
                        "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 0)))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void checkRevocationStatusWrapsUnexpectedVerifierFailures() {
        StatusListVerifier failingVerifier = new StatusListVerifier() {
            @Override
            DecodedStatusList fetchAndDecodeStatusList(String uri) throws Exception {
                throw new RuntimeException("simulated status list fetch failure");
            }
        };

        assertThatThrownBy(() -> failingVerifier.checkRevocationStatus(Map.of(
                        "status", Map.of("status_list", Map.of("uri", "https://issuer.example/status", "idx", 0)))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unable to verify credential revocation status");
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

    // --- validateStatusListToken tests ---

    @Test
    void validateStatusListTokenAcceptsValidToken() {
        verifier.validateStatusListToken(
                "statuslist+jwt",
                "https://issuer.example/status/1",
                Instant.now().plusSeconds(3600),
                "https://issuer.example/status/1");
    }

    @Test
    void validateStatusListTokenAcceptsNoExpiration() {
        verifier.validateStatusListToken(
                "statuslist+jwt", "https://issuer.example/status/1", null, "https://issuer.example/status/1");
    }

    @Test
    void validateStatusListTokenRejectsWrongTyp() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "jwt", "https://issuer.example/status/1", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("statuslist+jwt");
    }

    @Test
    void validateStatusListTokenRejectsMissingTyp() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        null, "https://issuer.example/status/1", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("statuslist+jwt");
    }

    @Test
    void validateStatusListTokenRejectsSubMismatch() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "statuslist+jwt", "https://other.example/status/2", null, "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void validateStatusListTokenRejectsExpiredToken() {
        assertThatThrownBy(() -> verifier.validateStatusListToken(
                        "statuslist+jwt",
                        "https://issuer.example/status/1",
                        Instant.now().minusSeconds(60),
                        "https://issuer.example/status/1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("expired");
    }

    // --- resolveExpiry tests ---

    @Test
    void resolveExpiryUsesTtlClaim() {
        Instant expiry = verifier.resolveExpiry(null, 300);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(290));
        assertThat(expiry).isBefore(Instant.now().plusSeconds(310));
    }

    @Test
    void resolveExpiryPrefersEarlierOfTtlAndExp() {
        Instant expiry = verifier.resolveExpiry(Instant.now().plusSeconds(3600), 300);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(310));
    }

    @Test
    void resolveExpiryPrefersExpWhenEarlierThanTtl() {
        Instant expTime = Instant.now().plusSeconds(120);
        Instant expiry = verifier.resolveExpiry(expTime, 3600);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(130));
        assertThat(expiry).isAfter(Instant.now().plusSeconds(110));
    }

    @Test
    void resolveExpiryFallsBackToExpWhenNoTtl() {
        Instant expTime = Instant.now().plusSeconds(600);
        Instant expiry = verifier.resolveExpiry(expTime, null);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(595));
        assertThat(expiry).isBefore(Instant.now().plusSeconds(605));
    }

    @Test
    void resolveExpiryReturnsNowWhenNeitherTtlNorExp() {
        Instant before = Instant.now();
        Instant expiry = verifier.resolveExpiry(null, null);
        assertThat(expiry).isAfterOrEqualTo(before);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(2));
    }

    @Test
    void resolveExpiryCapsAtMaxCacheTtl() {
        StatusListVerifier capped = new StatusListVerifier(null, null, Duration.ofSeconds(60));
        Instant expiry = capped.resolveExpiry(null, 3600);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(65));
        assertThat(expiry).isAfter(Instant.now().plusSeconds(55));
    }

    @Test
    void resolveExpiryIgnoresNonPositiveTtl() {
        Instant expiry = verifier.resolveExpiry(Instant.now().plusSeconds(600), 0);
        assertThat(expiry).isAfter(Instant.now().plusSeconds(595));
    }

    @Test
    void resolveExpiryFallsBackToNowForNegativeTtlWithoutExp() {
        Instant before = Instant.now();
        Instant expiry = verifier.resolveExpiry(null, -60);
        assertThat(expiry).isAfterOrEqualTo(before);
        assertThat(expiry).isBefore(Instant.now().plusSeconds(2));
    }
}
