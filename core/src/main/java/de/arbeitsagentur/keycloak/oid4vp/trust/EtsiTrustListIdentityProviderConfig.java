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

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

/**
 * Configuration of the OID4VP trust material identity provider.
 *
 * <p>Trust anchors come from an ETSI TS 119 602 trust list URL (fetched, cached and refreshed by
 * {@code TrustListProvider}), from a pasted PEM certificate bundle, or both. The
 * {@code trustedCertificates} and {@code requiredExtendedKeyUsages} keys match the upstream
 * {@code DefaultTrustIdentityProviderConfig} so instances migrate cleanly once Keycloak ships
 * X.509 trust material support.
 */
public class EtsiTrustListIdentityProviderConfig extends IdentityProviderModel {

    public static final String TRUST_LIST_URL = "trustListUrl";
    public static final String TRUST_LIST_SIGNING_CERT_PEM = "trustListSigningCertPem";
    public static final String TRUST_LIST_LOTE_TYPE = "trustListLoTEType";
    public static final String TRUST_LIST_MAX_CACHE_TTL_SECONDS = "trustListMaxCacheTtlSeconds";
    public static final String TRUST_LIST_MAX_STALE_AGE_SECONDS = "trustListMaxStaleAgeSeconds";
    public static final String TRUSTED_CERTIFICATES = "trustedCertificates";
    public static final String REQUIRED_EXTENDED_KEY_USAGES = "requiredExtendedKeyUsages";

    public static final int DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS = 86400;

    public EtsiTrustListIdentityProviderConfig() {}

    public EtsiTrustListIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        boolean hasTrustListUrl = StringUtil.isNotBlank(getTrustListUrl());
        boolean hasTrustedCertificates = StringUtil.isNotBlank(getTrustedCertificates());
        if (!hasTrustListUrl && !hasTrustedCertificates) {
            throw new IllegalArgumentException(
                    "Configure a trust list URL or trusted certificates on the trust material identity provider");
        }
        if (hasTrustedCertificates && parseTrustedCertificates().isEmpty()) {
            throw new IllegalArgumentException("Trusted certificates must be a PEM bundle of X.509 certificates");
        }
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

    public String getTrustListLoTEType() {
        return getConfig().get(TRUST_LIST_LOTE_TYPE);
    }

    public void setTrustListLoTEType(String value) {
        getConfig().put(TRUST_LIST_LOTE_TYPE, value);
    }

    public Duration getTrustListMaxCacheTtl() {
        return parseDurationSeconds(getConfig().get(TRUST_LIST_MAX_CACHE_TTL_SECONDS));
    }

    public void setTrustListMaxCacheTtlSeconds(int seconds) {
        getConfig().put(TRUST_LIST_MAX_CACHE_TTL_SECONDS, String.valueOf(seconds));
    }

    public Duration getTrustListMaxStaleAge() {
        String value = getConfig().get(TRUST_LIST_MAX_STALE_AGE_SECONDS);
        if (StringUtil.isBlank(value)) {
            return Duration.ofSeconds(DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS);
        }
        Duration parsed = parseDurationSeconds(value);
        return parsed != null ? parsed : Duration.ofSeconds(DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS);
    }

    public void setTrustListMaxStaleAgeSeconds(int seconds) {
        getConfig().put(TRUST_LIST_MAX_STALE_AGE_SECONDS, String.valueOf(seconds));
    }

    public String getTrustedCertificates() {
        return normalizePemConfigValue(getConfig().get(TRUSTED_CERTIFICATES));
    }

    public void setTrustedCertificates(String pem) {
        getConfig().put(TRUSTED_CERTIFICATES, pem);
    }

    public List<String> getRequiredExtendedKeyUsages() {
        String configured = getConfig().get(REQUIRED_EXTENDED_KEY_USAGES);
        if (StringUtil.isBlank(configured)) {
            return List.of();
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .distinct()
                .toList();
    }

    public void setRequiredExtendedKeyUsages(String commaSeparatedOids) {
        getConfig().put(REQUIRED_EXTENDED_KEY_USAGES, commaSeparatedOids);
    }

    /** Parses the pasted PEM bundle. Returns an empty list when unset or unparsable. */
    public List<X509Certificate> parseTrustedCertificates() {
        String pem = getTrustedCertificates();
        if (StringUtil.isBlank(pem)) {
            return List.of();
        }
        try {
            X509Certificate[] certificates = PemUtils.decodeCertificates(pem);
            return certificates != null ? List.of(certificates) : List.of();
        } catch (Exception e) {
            return List.of();
        }
    }

    /** Parses the trust list signing certificate PEM bundle. Returns null when unset. */
    public List<X509Certificate> parseTrustListSigningCerts() {
        String pem = getTrustListSigningCertPem();
        if (StringUtil.isBlank(pem)) {
            return null;
        }
        try {
            X509Certificate[] certificates = PemUtils.decodeCertificates(pem);
            return certificates != null && certificates.length > 0 ? List.of(certificates) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Duration parseDurationSeconds(String value) {
        if (StringUtil.isBlank(value)) {
            return null;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds >= 0 ? Duration.ofSeconds(seconds) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String normalizePemConfigValue(String pem) {
        return pem != null && pem.contains("\\n") ? pem.replace("\\n", "\n") : pem;
    }
}
