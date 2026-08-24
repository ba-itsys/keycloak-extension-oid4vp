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
package de.arbeitsagentur.keycloak.oid4vp.trust;

import static org.assertj.core.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EtsiTrustListIdentityProviderConfigTest {

    private EtsiTrustListIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        config = new EtsiTrustListIdentityProviderConfig();
    }

    @Test
    void trustListMaxCacheTtl_defaultIsNull() {
        assertThat(config.getTrustListMaxCacheTtl()).isNull();
    }

    @Test
    void trustListMaxCacheTtl_parsesSeconds() {
        config.setTrustListMaxCacheTtlSeconds(120);
        assertThat(config.getTrustListMaxCacheTtl()).isEqualTo(Duration.ofSeconds(120));
    }

    @Test
    void trustListLoTEType_defaultsToEmpty() {
        assertThat(config.getTrustListLoTEType()).isNull();
    }

    @Test
    void trustListSigningCertPem_normalizesEscapedLineBreaks() {
        config.setTrustListSigningCertPem("-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----");
        assertThat(config.getTrustListSigningCertPem())
                .isEqualTo("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----");
    }

    @Test
    void trustListSigningCertPem_keepsRealLineBreaks() {
        config.setTrustListSigningCertPem("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----");
        assertThat(config.getTrustListSigningCertPem())
                .isEqualTo("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----");
    }

    @Test
    void trustListSigningCertPem_decodesBase64EncodedValue() {
        String pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";
        config.setTrustListSigningCertPem(Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.getTrustListSigningCertPem()).isEqualTo(pem);
    }

    @Test
    void trustedCertificates_decodesBase64EncodedValue() {
        String pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";
        config.setTrustedCertificates(Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.getTrustedCertificates()).isEqualTo(pem);
    }

    @Test
    void trustListMaxCacheTtl_ignoresInvalidAndNegativeValues() {
        config.setTrustListMaxCacheTtlSeconds(-5);
        assertThat(config.getTrustListMaxCacheTtl()).isNull();
    }

    @Test
    void trustListMaxStaleAge_defaultsToOneDayAndParsesSeconds() {
        assertThat(config.getTrustListMaxStaleAge()).isEqualTo(Duration.ofSeconds(86400));

        config.setTrustListMaxStaleAgeSeconds(0);
        assertThat(config.getTrustListMaxStaleAge()).isEqualTo(Duration.ZERO);

        config.setTrustListMaxStaleAgeSeconds(-1);
        assertThat(config.getTrustListMaxStaleAge()).isEqualTo(Duration.ofSeconds(86400));
    }

    @Test
    void requiredExtendedKeyUsages_parsesCommaSeparatedDistinctOids() {
        assertThat(config.getRequiredExtendedKeyUsages()).isEmpty();

        config.setRequiredExtendedKeyUsages(" 1.0.18013.5.1.2 , 1.3.6.1.5.5.7.3.3 , 1.0.18013.5.1.2 ,, ");
        assertThat(config.getRequiredExtendedKeyUsages()).containsExactly("1.0.18013.5.1.2", "1.3.6.1.5.5.7.3.3");
    }

    @Test
    void validate_acceptsTrustListUrlOnly() {
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.validate(null);
    }

    @Test
    void parseTrustedCertificates_returnsEmptyForBlankOrGarbage() {
        assertThat(config.parseTrustedCertificates()).isEmpty();

        config.setTrustedCertificates("garbage");
        assertThat(config.parseTrustedCertificates()).isEmpty();
    }

    @Test
    void validate_rejectsUnparsableTrustListSigningCert() {
        config.setTrustListUrl("https://tl.example/list.jwt");
        config.setTrustListSigningCertPem("garbage");

        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trust list signing certificate");
    }

    @Test
    void parseTrustListSigningCerts_returnsNullWhenUnset() {
        assertThat(config.parseTrustListSigningCerts()).isNull();
    }

    @Test
    void parseTrustListSigningCerts_throwsForGarbage() {
        config.setTrustListSigningCertPem("garbage");
        assertThatThrownBy(config::parseTrustListSigningCerts)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trust list signing certificate");
    }
}
