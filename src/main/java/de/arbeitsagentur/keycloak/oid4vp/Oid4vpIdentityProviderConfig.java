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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import java.time.Duration;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.utils.StringUtil;

/**
 * Configuration model for the OID4VP Identity Provider.
 *
 * <p>Wraps the Keycloak {@link IdentityProviderModel} and provides typed accessors for all
 * OID4VP-specific settings: credential formats, client ID schemes, HAIP enforcement, trust list
 * URL, SSE polling parameters, and claim mappings. Implements {@link Oid4vpConfigProvider} for
 * use by domain services without depending on the full Keycloak model.
 */
public class Oid4vpIdentityProviderConfig extends IdentityProviderModel implements Oid4vpConfigProvider {

    public static final String DCQL_QUERY = "dcqlQuery";
    public static final String USER_MAPPING_CLAIM = "userMappingClaim";
    public static final String USER_MAPPING_CLAIM_MDOC = "userMappingClaimMdoc";
    public static final String TRANSIENT_USERS = IdentityProviderModel.DO_NOT_STORE_USERS;

    public static final String SAME_DEVICE_ENABLED = "sameDeviceEnabled";
    public static final String CROSS_DEVICE_ENABLED = "crossDeviceEnabled";
    public static final String WALLET_SCHEME = "walletScheme";

    public static final String CLIENT_ID_SCHEME = "clientIdScheme";
    public static final String RESPONSE_MODE = "responseMode";
    public static final String X509_CERTIFICATE_PEM = "x509CertificatePem";
    public static final String X509_SIGNING_KEY_JWK = "x509SigningKeyJwk";

    public static final String VERIFIER_INFO = "verifierInfo";

    public static final String CREDENTIAL_SET_MODE = "credentialSetMode";
    public static final String CREDENTIAL_SET_MODE_OPTIONAL = "optional";
    public static final String CREDENTIAL_SET_MODE_ALL = "all";
    public static final String CREDENTIAL_SET_PURPOSE = "credentialSetPurpose";

    public static final String TRUST_LIST_URL = "trustListUrl";
    public static final String TRUST_LIST_SIGNING_CERT_PEM = "trustListSigningCertPem";
    public static final String TRUSTED_AUTHORITIES_MODE = "trustedAuthoritiesMode";

    public static final String ALLOWED_ISSUERS = "allowedIssuers";
    public static final String ALLOWED_CREDENTIAL_TYPES = "allowedCredentialTypes";

    public static final String STATUS_LIST_MAX_CACHE_TTL_SECONDS = "statusListMaxCacheTtlSeconds";
    public static final String TRUST_LIST_MAX_CACHE_TTL_SECONDS = "trustListMaxCacheTtlSeconds";
    public static final String TRUST_LIST_MAX_STALE_AGE_SECONDS = "trustListMaxStaleAgeSeconds";
    public static final String ISSUER_METADATA_MAX_CACHE_TTL_SECONDS = "issuerMetadataMaxCacheTtlSeconds";
    public static final int DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS = 86400;
    public static final int DEFAULT_ISSUER_METADATA_MAX_CACHE_TTL_SECONDS = 86400;

    public static final String SSE_POLL_INTERVAL_MS = "ssePollIntervalMs";
    public static final String SSE_TIMEOUT_SECONDS = "sseTimeoutSeconds";
    public static final String SSE_PING_INTERVAL_SECONDS = "ssePingIntervalSeconds";
    public static final String CROSS_DEVICE_COMPLETE_TTL_SECONDS = "crossDeviceCompleteTtlSeconds";

    public static final String CLOCK_SKEW_SECONDS = "clockSkewSeconds";
    public static final String KB_JWT_MAX_AGE_SECONDS = "kbJwtMaxAgeSeconds";
    public static final String REQUEST_OBJECT_LIFESPAN_SECONDS = "requestObjectLifespanSeconds";

    public static final int DEFAULT_SSE_POLL_INTERVAL_MS = 2000;
    public static final int DEFAULT_SSE_TIMEOUT_SECONDS = 120;
    public static final int DEFAULT_SSE_PING_INTERVAL_SECONDS = 10;
    public static final int DEFAULT_CROSS_DEVICE_COMPLETE_TTL_SECONDS = 300;
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final int DEFAULT_KB_JWT_MAX_AGE_SECONDS = 300;
    public static final int DEFAULT_REQUEST_OBJECT_LIFESPAN_SECONDS = 10;

    public static final String USE_ID_TOKEN_SUBJECT = "useIdTokenSubject";

    public static final String ENFORCE_HAIP = "enforceHaip";

    public Oid4vpIdentityProviderConfig() {
        super();
    }

    public Oid4vpIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getDcqlQuery() {
        return getConfig().get(DCQL_QUERY);
    }

    public void setDcqlQuery(String dcqlQuery) {
        getConfig().put(DCQL_QUERY, dcqlQuery);
    }

    public String getUserMappingClaim() {
        String claim = getConfig().get(USER_MAPPING_CLAIM);
        return StringUtil.isNotBlank(claim) ? claim : "sub";
    }

    public void setUserMappingClaim(String userMappingClaim) {
        getConfig().put(USER_MAPPING_CLAIM, userMappingClaim);
    }

    public String getUserMappingClaimMdoc() {
        String claim = getConfig().get(USER_MAPPING_CLAIM_MDOC);
        return StringUtil.isNotBlank(claim) ? claim : getUserMappingClaim();
    }

    public void setUserMappingClaimMdoc(String userMappingClaimMdoc) {
        getConfig().put(USER_MAPPING_CLAIM_MDOC, userMappingClaimMdoc);
    }

    public String getUserMappingClaimForFormat(String format) {
        if (Oid4vpConstants.FORMAT_MSO_MDOC.equalsIgnoreCase(format)) {
            return getUserMappingClaimMdoc();
        }
        return getUserMappingClaim();
    }

    public boolean isSameDeviceEnabled() {
        return getBoolConfig(SAME_DEVICE_ENABLED, true);
    }

    public void setSameDeviceEnabled(boolean enabled) {
        getConfig().put(SAME_DEVICE_ENABLED, String.valueOf(enabled));
    }

    public boolean isCrossDeviceEnabled() {
        return getBoolConfig(CROSS_DEVICE_ENABLED, true);
    }

    public void setCrossDeviceEnabled(boolean enabled) {
        getConfig().put(CROSS_DEVICE_ENABLED, String.valueOf(enabled));
    }

    public String getWalletScheme() {
        String scheme = getConfig().get(WALLET_SCHEME);
        return StringUtil.isNotBlank(scheme) ? scheme : Oid4vpConstants.DEFAULT_WALLET_SCHEME;
    }

    public void setWalletScheme(String scheme) {
        getConfig().put(WALLET_SCHEME, scheme);
    }

    public String getClientIdScheme() {
        return getResolvedClientIdScheme().configValue();
    }

    public Oid4vpClientIdScheme getResolvedClientIdScheme() {
        return Oid4vpClientIdScheme.resolve(getConfig().get(CLIENT_ID_SCHEME), isEnforceHaip());
    }

    public void setClientIdScheme(String scheme) {
        getConfig().put(CLIENT_ID_SCHEME, scheme);
    }

    public String getResponseMode() {
        return getResolvedResponseMode().parameterValue();
    }

    public Oid4vpResponseMode getResolvedResponseMode() {
        return Oid4vpResponseMode.resolve(getConfig().get(RESPONSE_MODE), isEnforceHaip());
    }

    public void setResponseMode(String responseMode) {
        getConfig().put(RESPONSE_MODE, responseMode);
    }

    public String getX509CertificatePem() {
        return normalizePemConfigValue(getConfig().get(X509_CERTIFICATE_PEM));
    }

    public void setX509CertificatePem(String pem) {
        getConfig().put(X509_CERTIFICATE_PEM, pem);
    }

    public String getX509SigningKeyJwk() {
        return getConfig().get(X509_SIGNING_KEY_JWK);
    }

    public void setX509SigningKeyJwk(String jwk) {
        getConfig().put(X509_SIGNING_KEY_JWK, jwk);
    }

    public String getVerifierInfo() {
        return getConfig().get(VERIFIER_INFO);
    }

    public void setVerifierInfo(String verifierInfo) {
        getConfig().put(VERIFIER_INFO, verifierInfo);
    }

    public String getCredentialSetMode() {
        String mode = getConfig().get(CREDENTIAL_SET_MODE);
        return StringUtil.isNotBlank(mode) ? mode : CREDENTIAL_SET_MODE_OPTIONAL;
    }

    public void setCredentialSetMode(String mode) {
        getConfig().put(CREDENTIAL_SET_MODE, mode);
    }

    public boolean isAllCredentialsRequired() {
        return CREDENTIAL_SET_MODE_ALL.equals(getCredentialSetMode());
    }

    public String getCredentialSetPurpose() {
        return getConfig().get(CREDENTIAL_SET_PURPOSE);
    }

    public void setCredentialSetPurpose(String purpose) {
        getConfig().put(CREDENTIAL_SET_PURPOSE, purpose);
    }

    public String getTrustListUrl() {
        return getConfig().get(TRUST_LIST_URL);
    }

    public void setTrustListUrl(String url) {
        getConfig().put(TRUST_LIST_URL, url);
    }

    public String getTrustListSigningCertPem() {
        return normalizePemConfigValue(getConfig().get(TRUST_LIST_SIGNING_CERT_PEM));
    }

    public void setTrustListSigningCertPem(String pem) {
        getConfig().put(TRUST_LIST_SIGNING_CERT_PEM, pem);
    }

    public Oid4vpTrustedAuthoritiesMode getTrustedAuthoritiesMode() {
        return Oid4vpTrustedAuthoritiesMode.resolve(getConfig().get(TRUSTED_AUTHORITIES_MODE));
    }

    public void setTrustedAuthoritiesMode(String mode) {
        getConfig().put(TRUSTED_AUTHORITIES_MODE, mode);
    }

    public boolean isEnforceHaip() {
        return getBoolConfig(ENFORCE_HAIP, true);
    }

    public void setEnforceHaip(boolean enforce) {
        getConfig().put(ENFORCE_HAIP, String.valueOf(enforce));
    }

    public boolean isUseIdTokenSubject() {
        return getBoolConfig(USE_ID_TOKEN_SUBJECT, false);
    }

    @Override
    public boolean isTransientUsersEnabled() {
        return getBoolConfig(TRANSIENT_USERS, false);
    }

    public void setTransientUsersEnabled(boolean enabled) {
        setTransientUsers(Boolean.valueOf(enabled));
    }

    public void setUseIdTokenSubject(boolean use) {
        getConfig().put(USE_ID_TOKEN_SUBJECT, String.valueOf(use));
    }

    public String getAllowedIssuers() {
        return getConfig().get(ALLOWED_ISSUERS);
    }

    public void setAllowedIssuers(String issuers) {
        getConfig().put(ALLOWED_ISSUERS, issuers);
    }

    public String getAllowedCredentialTypes() {
        return getConfig().get(ALLOWED_CREDENTIAL_TYPES);
    }

    public void setAllowedCredentialTypes(String types) {
        getConfig().put(ALLOWED_CREDENTIAL_TYPES, types);
    }

    public boolean isIssuerAllowed(String issuer) {
        return isValueAllowed(issuer, getAllowedIssuers());
    }

    public boolean isCredentialTypeAllowed(String credentialType) {
        return isValueAllowed(credentialType, getAllowedCredentialTypes());
    }

    public Duration getStatusListMaxCacheTtl() {
        return parseDurationSeconds(STATUS_LIST_MAX_CACHE_TTL_SECONDS);
    }

    public void setStatusListMaxCacheTtlSeconds(int seconds) {
        getConfig().put(STATUS_LIST_MAX_CACHE_TTL_SECONDS, String.valueOf(seconds));
    }

    public Duration getTrustListMaxCacheTtl() {
        return parseDurationSeconds(TRUST_LIST_MAX_CACHE_TTL_SECONDS);
    }

    public void setTrustListMaxCacheTtlSeconds(int seconds) {
        getConfig().put(TRUST_LIST_MAX_CACHE_TTL_SECONDS, String.valueOf(seconds));
    }

    public Duration getIssuerMetadataMaxCacheTtl() {
        String value = getConfig().get(ISSUER_METADATA_MAX_CACHE_TTL_SECONDS);
        if (StringUtil.isBlank(value)) {
            return Duration.ofSeconds(DEFAULT_ISSUER_METADATA_MAX_CACHE_TTL_SECONDS);
        }
        try {
            return Duration.ofSeconds(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return Duration.ofSeconds(DEFAULT_ISSUER_METADATA_MAX_CACHE_TTL_SECONDS);
        }
    }

    public void setIssuerMetadataMaxCacheTtlSeconds(int seconds) {
        getConfig().put(ISSUER_METADATA_MAX_CACHE_TTL_SECONDS, String.valueOf(seconds));
    }

    /**
     * Maximum age of a stale (expired) trust list cache entry that can be used as fallback when
     * a trust list refresh fails (e.g., network timeout). Defaults to 1 day (86400 seconds).
     * Set to 0 to disable stale cache usage entirely.
     */
    public Duration getTrustListMaxStaleAge() {
        String value = getConfig().get(TRUST_LIST_MAX_STALE_AGE_SECONDS);
        if (StringUtil.isBlank(value)) {
            return Duration.ofSeconds(DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS);
        }
        try {
            return Duration.ofSeconds(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return Duration.ofSeconds(DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS);
        }
    }

    public void setTrustListMaxStaleAgeSeconds(int seconds) {
        getConfig().put(TRUST_LIST_MAX_STALE_AGE_SECONDS, String.valueOf(seconds));
    }

    private Duration parseDurationSeconds(String configKey) {
        String value = getConfig().get(configKey);
        if (StringUtil.isBlank(value)) {
            return null;
        }
        try {
            return Duration.ofSeconds(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public int getSsePollIntervalMs() {
        return getIntConfig(SSE_POLL_INTERVAL_MS, DEFAULT_SSE_POLL_INTERVAL_MS);
    }

    public void setSsePollIntervalMs(int ms) {
        getConfig().put(SSE_POLL_INTERVAL_MS, String.valueOf(ms));
    }

    public int getSseTimeoutSeconds() {
        return getIntConfig(SSE_TIMEOUT_SECONDS, DEFAULT_SSE_TIMEOUT_SECONDS);
    }

    public void setSseTimeoutSeconds(int seconds) {
        getConfig().put(SSE_TIMEOUT_SECONDS, String.valueOf(seconds));
    }

    public int getSsePingIntervalSeconds() {
        return getIntConfig(SSE_PING_INTERVAL_SECONDS, DEFAULT_SSE_PING_INTERVAL_SECONDS);
    }

    public void setSsePingIntervalSeconds(int seconds) {
        getConfig().put(SSE_PING_INTERVAL_SECONDS, String.valueOf(seconds));
    }

    public int getCrossDeviceCompleteTtlSeconds() {
        return getIntConfig(CROSS_DEVICE_COMPLETE_TTL_SECONDS, DEFAULT_CROSS_DEVICE_COMPLETE_TTL_SECONDS);
    }

    public void setCrossDeviceCompleteTtlSeconds(int seconds) {
        getConfig().put(CROSS_DEVICE_COMPLETE_TTL_SECONDS, String.valueOf(seconds));
    }

    public int getClockSkewSeconds() {
        return getIntConfig(CLOCK_SKEW_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public void setClockSkewSeconds(int seconds) {
        getConfig().put(CLOCK_SKEW_SECONDS, String.valueOf(seconds));
    }

    public int getKbJwtMaxAgeSeconds() {
        return getIntConfig(KB_JWT_MAX_AGE_SECONDS, DEFAULT_KB_JWT_MAX_AGE_SECONDS);
    }

    public void setKbJwtMaxAgeSeconds(int seconds) {
        getConfig().put(KB_JWT_MAX_AGE_SECONDS, String.valueOf(seconds));
    }

    public int getRequestObjectLifespanSeconds() {
        return getIntConfig(REQUEST_OBJECT_LIFESPAN_SECONDS, DEFAULT_REQUEST_OBJECT_LIFESPAN_SECONDS);
    }

    public void setRequestObjectLifespanSeconds(int seconds) {
        getConfig().put(REQUEST_OBJECT_LIFESPAN_SECONDS, String.valueOf(seconds));
    }

    private int getIntConfig(String key, int defaultValue) {
        String value = getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private boolean getBoolConfig(String key, boolean defaultValue) {
        String value = getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return defaultValue;
        }
        return defaultValue ? !"false".equalsIgnoreCase(value) : "true".equalsIgnoreCase(value);
    }

    private boolean isValueAllowed(String value, String allowedList) {
        if (StringUtil.isBlank(allowedList) || "*".equals(allowedList.trim())) {
            return true;
        }
        if (value == null) {
            return false;
        }
        for (String entry : allowedList.split(",")) {
            if (entry.trim().equals(value)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizePemConfigValue(String pem) {
        return pem != null && pem.contains("\\n") ? pem.replace("\\n", "\n") : pem;
    }
}
