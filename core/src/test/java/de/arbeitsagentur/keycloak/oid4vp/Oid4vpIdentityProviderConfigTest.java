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

import static org.assertj.core.api.Assertions.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpRejectionResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.PrincipalAttribute;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Oid4vpIdentityProviderConfigTest {

    private Oid4vpIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        config = new Oid4vpIdentityProviderConfig();
    }

    @Test
    void isIssuerAllowed_wildcard_allowsAll() {
        config.setAllowedIssuers("*");
        assertThat(config.isIssuerAllowed("https://any-issuer.example")).isTrue();
    }

    @Test
    void isIssuerAllowed_empty_allowsAll() {
        assertThat(config.isIssuerAllowed("https://any-issuer.example")).isTrue();
    }

    @Test
    void isIssuerAllowed_specificList_matchesExact() {
        config.setAllowedIssuers("https://issuer1.example,https://issuer2.example");
        assertThat(config.isIssuerAllowed("https://issuer1.example")).isTrue();
        assertThat(config.isIssuerAllowed("https://issuer2.example")).isTrue();
        assertThat(config.isIssuerAllowed("https://other.example")).isFalse();
    }

    @Test
    void isIssuerAllowed_nullIssuer_notAllowed() {
        config.setAllowedIssuers("https://issuer1.example");
        assertThat(config.isIssuerAllowed(null)).isFalse();
    }

    @Test
    void defaultValues() {
        assertThat(config.getClientIdScheme()).isEqualTo("x509_hash");
        assertThat(config.getResponseMode()).isEqualTo("direct_post.jwt");
        assertThat(config.isTransientUsersEnabled()).isFalse();
        assertThat(config.isSameDeviceEnabled()).isTrue();
        assertThat(config.isCrossDeviceEnabled()).isTrue();
        assertThat(config.getCredentialSets()).isNull();
        assertThat(config.getPrincipalAttributesValue()).isNull();
    }

    @Test
    void clientIdScheme_respectsConfiguredValue() {
        config.setClientIdScheme("x509_san_dns");
        assertThat(config.getClientIdScheme()).isEqualTo("x509_san_dns");

        config.setClientIdScheme("plain");
        assertThat(config.getClientIdScheme()).isEqualTo("plain");
    }

    @Test
    void clientIdScheme_defaultsToX509HashWhenUnsetOrUnknown() {
        assertThat(config.getClientIdScheme()).isEqualTo("x509_hash");

        config.setClientIdScheme("bogus");
        assertThat(config.getClientIdScheme()).isEqualTo("x509_hash");
    }

    @Test
    void validate_rejectsCertificateBoundSchemeWithCertOnlyPem() {
        config.setClientIdScheme("x509_hash");
        config.setX509CertificatePem("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----");

        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no private key");
    }

    @Test
    void x509CertificatePem_decodesBase64EncodedValue() {
        String pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";
        config.setX509CertificatePem(Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.getX509CertificatePem()).isEqualTo(pem);
    }

    @Test
    void verifierInfo_decodesBase64EncodedJson() {
        String json = "[{\"format\":\"jwt\",\"data\":\"eyJhbGciOi...\"}]";
        config.setVerifierInfo(Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.getVerifierInfo()).isEqualTo(json);
    }

    @Test
    void x509SigningKeyJwk_decodesBase64EncodedJson() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\"}";
        config.setX509SigningKeyJwk(Base64.getEncoder().encodeToString(jwk.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.getX509SigningKeyJwk()).isEqualTo(jwk);
    }

    @Test
    void responseMode_respectsConfiguredValue() {
        config.setResponseMode("direct_post");
        assertThat(config.getResponseMode()).isEqualTo("direct_post");
    }

    @Test
    void responseMode_defaultsToDirectPostJwtWhenUnsetOrUnknown() {
        assertThat(config.getResponseMode()).isEqualTo("direct_post.jwt");

        config.setResponseMode("bogus");
        assertThat(config.getResponseMode()).isEqualTo("direct_post.jwt");
    }

    @Test
    void rejectionResponse_respectsConfiguredValue() {
        config.getConfig().put(Oid4vpIdentityProviderConfig.REJECTION_RESPONSE, "ERROR");

        assertThat(config.getRejectionResponse()).isEqualTo(Oid4vpRejectionResponse.ERROR);
        assertThat(config.getRejectionResponse().isError()).isTrue();
    }

    @Test
    void rejectionResponse_defaultsToRedirectWhenUnsetOrUnknown() {
        assertThat(config.getRejectionResponse()).isEqualTo(Oid4vpRejectionResponse.REDIRECT);
        assertThat(config.getRejectionResponse().isError()).isFalse();

        config.getConfig().put(Oid4vpIdentityProviderConfig.REJECTION_RESPONSE, "bogus");
        assertThat(config.getRejectionResponse()).isEqualTo(Oid4vpRejectionResponse.REDIRECT);
    }

    @Test
    void getPrincipalAttributes_readsTheConfiguredEntries() {
        config.setPrincipalAttributes("employee:sub");
        assertThat(config.getPrincipalAttributes()).containsExactly(new PrincipalAttribute("employee", "sub"));
    }

    @Test
    void sseDefaults() {
        assertThat(config.getSsePollIntervalMs()).isEqualTo(2000);
        assertThat(config.getSseTimeoutSeconds()).isEqualTo(120);
        assertThat(config.getSsePingIntervalSeconds()).isEqualTo(10);
        assertThat(config.getCrossDeviceCompleteTtlSeconds()).isEqualTo(300);
    }

    @Test
    void statusListMaxCacheTtl_defaultIsNull() {
        assertThat(config.getStatusListMaxCacheTtl()).isNull();
    }

    @Test
    void statusListMaxCacheTtl_parsesSeconds() {
        config.setStatusListMaxCacheTtlSeconds(30);
        assertThat(config.getStatusListMaxCacheTtl()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void statusListMaxCacheTtl_zeroDisablesCaching() {
        config.setStatusListMaxCacheTtlSeconds(0);
        assertThat(config.getStatusListMaxCacheTtl()).isEqualTo(Duration.ZERO);
    }

    @Test
    void issuerMetadataMaxCacheTtl_defaultsToOneDay() {
        assertThat(config.getIssuerMetadataMaxCacheTtl()).isEqualTo(Duration.ofDays(1));
    }

    @Test
    void issuerMetadataMaxCacheTtl_parsesSeconds() {
        config.setIssuerMetadataMaxCacheTtlSeconds(45);
        assertThat(config.getIssuerMetadataMaxCacheTtl()).isEqualTo(Duration.ofSeconds(45));
    }

    @Test
    void statusListMaxCacheTtl_invalidFallsBackToNull() {
        config.getConfig().put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "not-a-number");
        assertThat(config.getStatusListMaxCacheTtl()).isNull();
    }

    @Test
    void trustMaterialIdps_defaultIsNull() {
        assertThat(config.getTrustMaterialIdps()).isNull();
    }

    @Test
    void requestObjectLifespan_default() {
        assertThat(config.getRequestObjectLifespanSeconds()).isEqualTo(10);
    }

    @Test
    void requestObjectLifespan_invalidFallsBackToDefault() {
        config.getConfig().put("requestObjectLifespanSeconds", "not-a-number");
        assertThat(config.getRequestObjectLifespanSeconds()).isEqualTo(10);
    }

    @Test
    void sseInvalidIntFallsBackToDefault() {
        config.getConfig().put("ssePollIntervalMs", "not-a-number");
        config.getConfig().put("sseTimeoutSeconds", "");

        assertThat(config.getSsePollIntervalMs()).isEqualTo(2000);
        assertThat(config.getSseTimeoutSeconds()).isEqualTo(120);
    }

    @Test
    void maxLoa_unsetMeansNoCeiling() {
        assertThat(config.getSameDeviceMaxLoa()).isNull();
        assertThat(config.getCrossDeviceMaxLoa()).isNull();
    }

    @Test
    void maxLoa_readsConfiguredCeilings() {
        config.setSameDeviceMaxLoa(4);
        config.setCrossDeviceMaxLoa(3);

        assertThat(config.getSameDeviceMaxLoa()).isEqualTo(4);
        assertThat(config.getCrossDeviceMaxLoa()).isEqualTo(3);
    }

    @Test
    void maxLoa_blankMeansNoCeiling() {
        config.getConfig().put("crossDeviceMaxLoa", " ");
        assertThat(config.getCrossDeviceMaxLoa()).isNull();
    }

    @Test
    void maxLoa_setNullRemovesTheEntry() {
        config.setCrossDeviceMaxLoa(3);
        config.setCrossDeviceMaxLoa(null);
        assertThat(config.getConfig()).doesNotContainKey("crossDeviceMaxLoa");
    }

    @Test
    void maxLoa_invalidValueFails() {
        config.getConfig().put("crossDeviceMaxLoa", "substantial");

        assertThatThrownBy(() -> config.getCrossDeviceMaxLoa())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("crossDeviceMaxLoa");
    }
}
