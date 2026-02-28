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

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.utils.StringUtil;

public class Oid4vpIdentityProviderConfig extends IdentityProviderModel {

    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";

    public static final String DCQL_QUERY = "dcqlQuery";
    public static final String USER_MAPPING_CLAIM = "userMappingClaim";
    public static final String USER_MAPPING_CLAIM_MDOC = "userMappingClaimMdoc";

    public static final String SAME_DEVICE_ENABLED = "sameDeviceEnabled";
    public static final String CROSS_DEVICE_ENABLED = "crossDeviceEnabled";
    public static final String WALLET_SCHEME = "walletScheme";

    public static final String CLIENT_ID_SCHEME = "clientIdScheme";
    public static final String X509_CERTIFICATE_PEM = "x509CertificatePem";
    public static final String X509_SIGNING_KEY_JWK = "x509SigningKeyJwk";

    public static final String VERIFIER_INFO = "verifierInfo";

    public static final String CREDENTIAL_SET_MODE = "credentialSetMode";
    public static final String CREDENTIAL_SET_MODE_OPTIONAL = "optional";
    public static final String CREDENTIAL_SET_MODE_ALL = "all";
    public static final String CREDENTIAL_SET_PURPOSE = "credentialSetPurpose";

    public static final String TRUST_X5C_FROM_CREDENTIAL = "trustX5cFromCredential";
    public static final String ADDITIONAL_TRUSTED_CERTIFICATES = "additionalTrustedCertificates";
    public static final String SKIP_TRUST_LIST_VERIFICATION = "skipTrustListVerification";

    public static final String ALLOWED_ISSUERS = "allowedIssuers";
    public static final String ALLOWED_CREDENTIAL_TYPES = "allowedCredentialTypes";

    public static final String SSE_POLL_INTERVAL_MS = "ssePollIntervalMs";
    public static final String SSE_TIMEOUT_SECONDS = "sseTimeoutSeconds";
    public static final String SSE_PING_INTERVAL_SECONDS = "ssePingIntervalSeconds";
    public static final String CROSS_DEVICE_COMPLETE_TTL_SECONDS = "crossDeviceCompleteTtlSeconds";

    public static final int DEFAULT_SSE_POLL_INTERVAL_MS = 2000;
    public static final int DEFAULT_SSE_TIMEOUT_SECONDS = 120;
    public static final int DEFAULT_SSE_PING_INTERVAL_SECONDS = 10;
    public static final int DEFAULT_CROSS_DEVICE_COMPLETE_TTL_SECONDS = 300;

    public static final String ENFORCE_HAIP = "enforceHaip";
    public static final String HAIP_SIGNING_ALGORITHM = "ES256";
    public static final String HAIP_RESPONSE_MODE = "direct_post.jwt";
    public static final String HAIP_REQUEST_MODE = "signed";

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
        if (FORMAT_MSO_MDOC.equalsIgnoreCase(format)) {
            return getUserMappingClaimMdoc();
        }
        return getUserMappingClaim();
    }

    public boolean isSameDeviceEnabled() {
        String value = getConfig().get(SAME_DEVICE_ENABLED);
        return value == null || !"false".equalsIgnoreCase(value);
    }

    public void setSameDeviceEnabled(boolean enabled) {
        getConfig().put(SAME_DEVICE_ENABLED, String.valueOf(enabled));
    }

    public boolean isCrossDeviceEnabled() {
        String value = getConfig().get(CROSS_DEVICE_ENABLED);
        return value == null || !"false".equalsIgnoreCase(value);
    }

    public void setCrossDeviceEnabled(boolean enabled) {
        getConfig().put(CROSS_DEVICE_ENABLED, String.valueOf(enabled));
    }

    public String getWalletScheme() {
        String scheme = getConfig().get(WALLET_SCHEME);
        return StringUtil.isNotBlank(scheme) ? scheme : "openid4vp://";
    }

    public void setWalletScheme(String scheme) {
        getConfig().put(WALLET_SCHEME, scheme);
    }

    public String getClientIdScheme() {
        String scheme = getConfig().get(CLIENT_ID_SCHEME);
        return StringUtil.isNotBlank(scheme) ? scheme : "x509_san_dns";
    }

    public void setClientIdScheme(String scheme) {
        getConfig().put(CLIENT_ID_SCHEME, scheme);
    }

    public String getX509CertificatePem() {
        return getConfig().get(X509_CERTIFICATE_PEM);
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

    public boolean isTrustX5cFromCredential() {
        return "true".equalsIgnoreCase(getConfig().get(TRUST_X5C_FROM_CREDENTIAL));
    }

    public void setTrustX5cFromCredential(boolean trust) {
        getConfig().put(TRUST_X5C_FROM_CREDENTIAL, String.valueOf(trust));
    }

    public String getAdditionalTrustedCertificates() {
        return getConfig().get(ADDITIONAL_TRUSTED_CERTIFICATES);
    }

    public void setAdditionalTrustedCertificates(String certificates) {
        getConfig().put(ADDITIONAL_TRUSTED_CERTIFICATES, certificates);
    }

    public boolean isSkipTrustListVerification() {
        return "true".equalsIgnoreCase(getConfig().get(SKIP_TRUST_LIST_VERIFICATION));
    }

    public void setSkipTrustListVerification(boolean skip) {
        getConfig().put(SKIP_TRUST_LIST_VERIFICATION, String.valueOf(skip));
    }

    public boolean isEnforceHaip() {
        String value = getConfig().get(ENFORCE_HAIP);
        return value == null || !"false".equalsIgnoreCase(value);
    }

    public void setEnforceHaip(boolean enforce) {
        getConfig().put(ENFORCE_HAIP, String.valueOf(enforce));
    }

    public boolean isEncryptedResponseRequired() {
        return isEnforceHaip();
    }

    public boolean getEffectiveTrustX5cFromCredential() {
        if (isSkipTrustListVerification()) {
            return true;
        }
        if (isEnforceHaip()) {
            return false;
        }
        return isTrustX5cFromCredential();
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
}
