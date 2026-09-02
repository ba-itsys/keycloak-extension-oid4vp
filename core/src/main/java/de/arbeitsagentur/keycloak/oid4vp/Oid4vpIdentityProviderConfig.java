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

import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpCredentialSetsValidator;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpRejectionResponse;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PrincipalAttribute;
import de.arbeitsagentur.keycloak.oid4vp.util.ConfigValues;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder.AggregatedCredentials;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Typed accessors for the OID4VP settings of a Keycloak {@link IdentityProviderModel}. Implementing
 * {@link Oid4vpConfigProvider} lets the domain services read the configuration without depending on
 * the Keycloak model.
 */
public class Oid4vpIdentityProviderConfig extends IdentityProviderModel implements Oid4vpConfigProvider {

    public static final String TRANSIENT_USERS = IdentityProviderModel.DO_NOT_STORE_USERS;

    public static final String SAME_DEVICE_ENABLED = "sameDeviceEnabled";
    public static final String CROSS_DEVICE_ENABLED = "crossDeviceEnabled";

    /**
     * The highest requested level of authentication at which the same-device flow is offered, empty
     * for no ceiling. The level is the integer Keycloak derives from the client's acr_values or
     * claims request through the realm or client ACR-to-LoA mapping.
     */
    public static final String SAME_DEVICE_MAX_LOA = "sameDeviceMaxLoa";

    /** The same ceiling for the cross-device flow. See {@link #SAME_DEVICE_MAX_LOA}. */
    public static final String CROSS_DEVICE_MAX_LOA = "crossDeviceMaxLoa";

    public static final String WALLET_SCHEME = "walletScheme";
    public static final String REQUEST_URI_METHOD_POST = "requestUriMethodPost";

    public static final String CLIENT_ID_SCHEME = "clientIdScheme";
    public static final String RESPONSE_MODE = "responseMode";
    public static final String REJECTION_RESPONSE = "rejectionResponse";
    public static final String X509_CERTIFICATE_PEM = "x509CertificatePem";
    public static final String X509_SIGNING_KEY_JWK = "x509SigningKeyJwk";

    public static final String VERIFIER_INFO = "verifierInfo";

    public static final String CREDENTIAL_SETS = "credentialSets";
    public static final String PRINCIPAL_ATTRIBUTES = "principalAttributes";

    /** Comma separated aliases of trust material identity providers. Same key as upstream. */
    public static final String TRUST_MATERIAL_IDPS = "trustMaterialIdps";

    /**
     * Whether a presentation without the subject credential is expected, in which case the verifier
     * generates a pseudonymous subject and the login that follows establishes which user it belongs
     * to. Otherwise the login fails because nothing identified the user.
     */
    public static final String ALLOW_MISSING_SUBJECT_CREDENTIAL = "allowMissingSubjectCredential";

    public static final String ALLOWED_ISSUERS = "allowedIssuers";

    public static final String STATUS_LIST_MAX_CACHE_TTL_SECONDS = "statusListMaxCacheTtlSeconds";
    public static final String ISSUER_METADATA_MAX_CACHE_TTL_SECONDS = "issuerMetadataMaxCacheTtlSeconds";
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

    public Oid4vpIdentityProviderConfig() {
        super();
    }

    public Oid4vpIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
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

    public Integer getSameDeviceMaxLoa() {
        return getOptionalIntConfig(SAME_DEVICE_MAX_LOA);
    }

    public void setSameDeviceMaxLoa(Integer maxLoa) {
        if (maxLoa == null) {
            getConfig().remove(SAME_DEVICE_MAX_LOA);
        } else {
            getConfig().put(SAME_DEVICE_MAX_LOA, String.valueOf(maxLoa));
        }
    }

    public Integer getCrossDeviceMaxLoa() {
        return getOptionalIntConfig(CROSS_DEVICE_MAX_LOA);
    }

    public void setCrossDeviceMaxLoa(Integer maxLoa) {
        if (maxLoa == null) {
            getConfig().remove(CROSS_DEVICE_MAX_LOA);
        } else {
            getConfig().put(CROSS_DEVICE_MAX_LOA, String.valueOf(maxLoa));
        }
    }

    public String getWalletScheme() {
        String scheme = getConfig().get(WALLET_SCHEME);
        return StringUtil.isNotBlank(scheme) ? scheme : Oid4vpConstants.DEFAULT_WALLET_SCHEME;
    }

    public void setWalletScheme(String scheme) {
        getConfig().put(WALLET_SCHEME, scheme);
    }

    /**
     * Whether the authorization request advertises {@code request_uri_method=post}, so that a
     * conforming wallet retrieves the request object with POST (OID4VP 1.0 §5.10) and sends its
     * {@code wallet_metadata} and {@code wallet_nonce} along, which is what enables request object
     * encryption and wallet nonce replay protection. Without the parameter the wallet has to use
     * GET and those features stay unreachable, but it is off by default because a wallet that
     * cannot POST the request object would be unable to start the flow at all.
     */
    public boolean isRequestUriMethodPost() {
        return getBoolConfig(REQUEST_URI_METHOD_POST, false);
    }

    public void setRequestUriMethodPost(boolean requestUriMethodPost) {
        getConfig().put(REQUEST_URI_METHOD_POST, String.valueOf(requestUriMethodPost));
    }

    public String getClientIdScheme() {
        return getResolvedClientIdScheme().configValue();
    }

    public Oid4vpClientIdScheme getResolvedClientIdScheme() {
        return Oid4vpClientIdScheme.resolve(getConfig().get(CLIENT_ID_SCHEME));
    }

    public void setClientIdScheme(String scheme) {
        getConfig().put(CLIENT_ID_SCHEME, scheme);
    }

    public String getResponseMode() {
        return getResolvedResponseMode().parameterValue();
    }

    public Oid4vpResponseMode getResolvedResponseMode() {
        return Oid4vpResponseMode.resolve(getConfig().get(RESPONSE_MODE));
    }

    public void setResponseMode(String responseMode) {
        getConfig().put(RESPONSE_MODE, responseMode);
    }

    public Oid4vpRejectionResponse getRejectionResponse() {
        return Oid4vpRejectionResponse.resolve(getConfig().get(REJECTION_RESPONSE));
    }

    public String getX509CertificatePem() {
        return ConfigValues.pem(getConfig().get(X509_CERTIFICATE_PEM));
    }

    public void setX509CertificatePem(String pem) {
        getConfig().put(X509_CERTIFICATE_PEM, pem);
    }

    public String getX509SigningKeyJwk() {
        return ConfigValues.json(getConfig().get(X509_SIGNING_KEY_JWK));
    }

    public void setX509SigningKeyJwk(String jwk) {
        getConfig().put(X509_SIGNING_KEY_JWK, jwk);
    }

    public String getVerifierInfo() {
        return ConfigValues.json(getConfig().get(VERIFIER_INFO));
    }

    public void setVerifierInfo(String verifierInfo) {
        getConfig().put(VERIFIER_INFO, verifierInfo);
    }

    /**
     * Rejects a broken credential set configuration in the admin console instead of at login time.
     * Keycloak calls this when the identity provider is created or updated, and on create the
     * provider has no mappers yet, so only the rules that need no mapper knowledge apply. Identity
     * provider mappers have no validation hook of their own, which is why the same rules run again
     * when the DCQL query is built.
     */
    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);

        // Parsing the ceilings here rejects a mistyped value when the provider is saved, instead
        // of failing every login afterwards.
        getSameDeviceMaxLoa();
        getCrossDeviceMaxLoa();

        if (getResolvedClientIdScheme().isCertificateBound()
                && StringUtil.isNotBlank(getX509CertificatePem())
                && StringUtil.isBlank(getX509SigningKeyJwk())
                && !getX509CertificatePem().contains("-----BEGIN PRIVATE KEY-----")) {
            throw new IllegalArgumentException("The verifier certificate PEM contains no private key. A"
                    + " certificate-bound client_id_scheme signs the request object with the certificate's key, so the"
                    + " PEM must include the PRIVATE KEY block.");
        }

        AggregatedCredentials aggregated = configuredCredentials(realm);
        List<String> problems = new ArrayList<>(aggregated.problems());
        problems.addAll(Oid4vpCredentialSetsValidator.problems(
                getParsedCredentialSets(),
                aggregated.credentials(),
                getPrincipalAttributes(),
                !isTransientUsersEnabled(),
                isAllowMissingSubjectCredential()));
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException(String.join("; ", problems));
        }
    }

    /**
     * @throws IllegalArgumentException when the configured value is not a valid credential set list
     */
    public List<CredentialSet> getParsedCredentialSets() {
        return StringUtil.isBlank(getCredentialSets())
                ? List.of()
                : CredentialSet.parse(JsonSerialization.mapper, getCredentialSets());
    }

    private AggregatedCredentials configuredCredentials(RealmModel realm) {
        if (realm == null || StringUtil.isBlank(getAlias())) {
            return new AggregatedCredentials(Map.of(), List.of());
        }
        return DcqlQueryBuilder.aggregateFromMappers(realm.getIdentityProviderMappersByAliasStream(getAlias()), this);
    }

    public String getCredentialSets() {
        return getConfig().get(CREDENTIAL_SETS);
    }

    public void setCredentialSets(String credentialSetsJson) {
        getConfig().put(CREDENTIAL_SETS, credentialSetsJson);
    }

    public String getPrincipalAttributesValue() {
        return getConfig().get(PRINCIPAL_ATTRIBUTES);
    }

    public void setPrincipalAttributes(String principalAttributes) {
        getConfig().put(PRINCIPAL_ATTRIBUTES, principalAttributes);
    }

    /**
     * Returns the credentials the subject may be read from, in the configured order.
     *
     * @throws IllegalArgumentException when the configured value is not a valid entry list
     */
    @Override
    public List<PrincipalAttribute> getPrincipalAttributes() {
        return PrincipalAttribute.parse(getPrincipalAttributesValue());
    }

    public String getTrustMaterialIdps() {
        return getConfig().get(TRUST_MATERIAL_IDPS);
    }

    public void setTrustMaterialIdps(String aliases) {
        getConfig().put(TRUST_MATERIAL_IDPS, aliases);
    }

    @Override
    public boolean isAllowMissingSubjectCredential() {
        return getBoolConfig(ALLOW_MISSING_SUBJECT_CREDENTIAL, false);
    }

    public void setAllowMissingSubjectCredential(boolean allow) {
        getConfig().put(ALLOW_MISSING_SUBJECT_CREDENTIAL, String.valueOf(allow));
    }

    @Override
    public boolean isTransientUsersEnabled() {
        return getBoolConfig(TRANSIENT_USERS, false);
    }

    public void setTransientUsersEnabled(boolean enabled) {
        setTransientUsers(Boolean.valueOf(enabled));
    }

    public String getAllowedIssuers() {
        return getConfig().get(ALLOWED_ISSUERS);
    }

    public void setAllowedIssuers(String issuers) {
        getConfig().put(ALLOWED_ISSUERS, issuers);
    }

    public boolean isIssuerAllowed(String issuer) {
        return isValueAllowed(issuer, getAllowedIssuers());
    }

    public Duration getStatusListMaxCacheTtl() {
        return parseDurationSeconds(STATUS_LIST_MAX_CACHE_TTL_SECONDS);
    }

    public void setStatusListMaxCacheTtlSeconds(int seconds) {
        getConfig().put(STATUS_LIST_MAX_CACHE_TTL_SECONDS, String.valueOf(seconds));
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

    /**
     * Fails on an unparseable value instead of falling back to a default, because the max LoA
     * settings are ceilings and dropping a mistyped one would offer a flow at a level the
     * configuration forbids.
     */
    private Integer getOptionalIntConfig(String key) {
        String value = getConfig().get(key);
        if (StringUtil.isBlank(value)) {
            return null;
        }
        try {
            return Integer.valueOf(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid integer value '" + value + "' for " + key);
        }
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
}
