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

import java.time.Duration;
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
    void isCredentialTypeAllowed_wildcard_allowsAll() {
        config.setAllowedCredentialTypes("*");
        assertThat(config.isCredentialTypeAllowed("AnyType")).isTrue();
    }

    @Test
    void isCredentialTypeAllowed_empty_allowsAll() {
        assertThat(config.isCredentialTypeAllowed("AnyType")).isTrue();
    }

    @Test
    void isCredentialTypeAllowed_specificList_matchesExact() {
        config.setAllowedCredentialTypes("IdentityCredential,mDL");
        assertThat(config.isCredentialTypeAllowed("IdentityCredential")).isTrue();
        assertThat(config.isCredentialTypeAllowed("mDL")).isTrue();
        assertThat(config.isCredentialTypeAllowed("Other")).isFalse();
    }

    @Test
    void isCredentialTypeAllowed_nullType_notAllowed() {
        config.setAllowedCredentialTypes("IdentityCredential");
        assertThat(config.isCredentialTypeAllowed(null)).isFalse();
    }

    @Test
    void defaultValues() {
        assertThat(config.getUserMappingClaim()).isEqualTo("sub");
        assertThat(config.getClientIdScheme()).isEqualTo("x509_san_dns");
        assertThat(config.isSameDeviceEnabled()).isTrue();
        assertThat(config.isCrossDeviceEnabled()).isTrue();
        assertThat(config.isEnforceHaip()).isTrue();
        assertThat(config.getCredentialSetMode()).isEqualTo("optional");
        assertThat(config.isAllCredentialsRequired()).isFalse();
    }

    @Test
    void getUserMappingClaimMdoc_fallsBackToSdJwtClaim() {
        config.setUserMappingClaim("email");
        assertThat(config.getUserMappingClaimMdoc()).isEqualTo("email");
    }

    @Test
    void getUserMappingClaimMdoc_usesMdocSpecificIfSet() {
        config.setUserMappingClaim("email");
        config.setUserMappingClaimMdoc("org.iso.18013.5.1/email");
        assertThat(config.getUserMappingClaimMdoc()).isEqualTo("org.iso.18013.5.1/email");
    }

    @Test
    void getUserMappingClaimForFormat_sdJwt() {
        config.setUserMappingClaim("sub");
        assertThat(config.getUserMappingClaimForFormat("dc+sd-jwt")).isEqualTo("sub");
    }

    @Test
    void getUserMappingClaimForFormat_mdoc() {
        config.setUserMappingClaim("sub");
        config.setUserMappingClaimMdoc("mdoc-sub");
        assertThat(config.getUserMappingClaimForFormat("mso_mdoc")).isEqualTo("mdoc-sub");
    }

    @Test
    void sseDefaults() {
        assertThat(config.getSsePollIntervalMs()).isEqualTo(2000);
        assertThat(config.getSseTimeoutSeconds()).isEqualTo(120);
        assertThat(config.getSsePingIntervalSeconds()).isEqualTo(10);
        assertThat(config.getCrossDeviceCompleteTtlSeconds()).isEqualTo(300);
    }

    @Test
    void sseCustomValues() {
        config.setSsePollIntervalMs(500);
        config.setSseTimeoutSeconds(60);
        config.setSsePingIntervalSeconds(5);
        config.setCrossDeviceCompleteTtlSeconds(600);

        assertThat(config.getSsePollIntervalMs()).isEqualTo(500);
        assertThat(config.getSseTimeoutSeconds()).isEqualTo(60);
        assertThat(config.getSsePingIntervalSeconds()).isEqualTo(5);
        assertThat(config.getCrossDeviceCompleteTtlSeconds()).isEqualTo(600);
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
    void statusListMaxCacheTtl_invalidFallsBackToNull() {
        config.getConfig().put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "not-a-number");
        assertThat(config.getStatusListMaxCacheTtl()).isNull();
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
    void sseInvalidIntFallsBackToDefault() {
        config.getConfig().put("ssePollIntervalMs", "not-a-number");
        config.getConfig().put("sseTimeoutSeconds", "");

        assertThat(config.getSsePollIntervalMs()).isEqualTo(2000);
        assertThat(config.getSseTimeoutSeconds()).isEqualTo(120);
    }
}
