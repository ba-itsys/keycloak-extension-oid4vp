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

import de.arbeitsagentur.keycloak.oid4vp.event.Oid4vpEventService;
import de.arbeitsagentur.keycloak.oid4vp.event.TrustMaterialFailedEvent;
import de.arbeitsagentur.keycloak.oid4vp.util.CertificateFingerprints;
import de.arbeitsagentur.keycloak.oid4vp.util.FailureDetails;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.ServiceDigitalIdentity;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustListJwt;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustedEntity;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustedEntityService;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.X509CertificateEntry;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * Fetches and caches an ETSI TS 119 602 trust list JWT and extracts its issuance and revocation
 * service certificates. A configured signing certificate verifies the JWT signature before any
 * certificate is extracted. Without one the JWT is accepted unverified and a warning is logged.
 */
public class TrustListProvider {

    private static final Logger LOG = Logger.getLogger(TrustListProvider.class);
    private static final ConcurrentHashMap<CacheKey, CachedTrustList> CACHE = new ConcurrentHashMap<>();
    private static final Set<CacheKey> WARNED_UNSIGNED_TRUST_LISTS = ConcurrentHashMap.newKeySet();
    static final Duration DEFAULT_MAX_STALE_AGE = Duration.ofDays(1);
    private static final String SERVICE_TYPE_SUFFIX_ISSUANCE = "/Issuance";
    private static final String SERVICE_TYPE_SUFFIX_REVOCATION = "/Revocation";
    private static final Duration FAILED_REFRESH_RETRY = Duration.ofMinutes(1);
    private static final int CONNECT_TIMEOUT_MILLIS = 3000;
    private static final String UNAVAILABLE_ATTRIBUTE = "oid4vp.trust-list.unavailable";
    private static final Map<CacheKey, Instant> RETRY_AFTER = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final String providerId;
    private final String trustListUrl;
    private final List<X509Certificate> staticCertificates;
    private final Duration maxCacheTtl;
    private final Duration maxStaleAge;
    private final List<X509Certificate> signingCertificates;
    private final List<String> serviceStatuses;
    private volatile String currentLoTEType;

    TrustListProvider(KeycloakSession session, String trustListUrl) {
        this(session, trustListUrl, null, null, null);
    }

    TrustListProvider(
            KeycloakSession session,
            String trustListUrl,
            Duration maxCacheTtl,
            List<X509Certificate> signingCertificates) {
        this(session, trustListUrl, maxCacheTtl, null, signingCertificates);
    }

    TrustListProvider(
            KeycloakSession session,
            String trustListUrl,
            Duration maxCacheTtl,
            Duration maxStaleAge,
            List<X509Certificate> signingCertificates) {
        this(session, null, trustListUrl, maxCacheTtl, maxStaleAge, signingCertificates, List.of());
    }

    // Keys the cache by provider id, so providers sharing a trust list stay isolated.
    public TrustListProvider(
            KeycloakSession session,
            String providerId,
            String trustListUrl,
            Duration maxCacheTtl,
            Duration maxStaleAge,
            List<X509Certificate> signingCertificates,
            List<String> serviceStatuses) {
        this.session = session;
        this.providerId = providerId;
        this.trustListUrl = trustListUrl;
        this.staticCertificates = null;
        this.maxCacheTtl = maxCacheTtl;
        this.maxStaleAge = maxStaleAge != null ? maxStaleAge : DEFAULT_MAX_STALE_AGE;
        this.signingCertificates = signingCertificates;
        this.serviceStatuses = List.copyOf(serviceStatuses);
    }

    public TrustListProvider(List<X509Certificate> staticCertificates) {
        this.session = null;
        this.providerId = null;
        this.trustListUrl = null;
        this.staticCertificates = staticCertificates != null ? List.copyOf(staticCertificates) : null;
        this.maxCacheTtl = null;
        this.maxStaleAge = DEFAULT_MAX_STALE_AGE;
        this.signingCertificates = null;
        this.serviceStatuses = List.of();
    }

    public List<X509Certificate> getIssuanceCertificates() {
        if (staticCertificates != null) {
            return staticCertificates;
        }
        return getTrustedTrustList().issuanceCertificates();
    }

    public List<X509Certificate> getRevocationCertificates() {
        if (staticCertificates != null) {
            return staticCertificates;
        }
        return getTrustedTrustList().revocationCertificates();
    }

    List<X509Certificate> getTrustedCertificates() {
        if (staticCertificates != null) return staticCertificates;
        return getTrustedTrustList().certificates();
    }

    private CachedTrustList getTrustedTrustList() {
        if (trustListUrl == null || trustListUrl.isBlank()) {
            return CachedTrustList.empty();
        }

        CacheKey cacheKey = cacheKey();
        CachedTrustList cached = CACHE.get(cacheKey);
        if (cached != null && cached.isValid()) {
            currentLoTEType = cached.loTEType;
            LOG.debugf("Using cached trust list for %s (expires %s)", trustListUrl, cached.expiresAt);
            return cached;
        }
        // Skips the download only with a copy to use, so a login never fails on a past failure.
        boolean staleCopy = cached != null && !cached.certificates.isEmpty() && staleCopyUsable(cached);
        if (staleCopy && Instant.now().isBefore(RETRY_AFTER.getOrDefault(cacheKey, Instant.MIN))) {
            currentLoTEType = cached.loTEType;
            return cached;
        }
        // Lets one login download while the others use the copy, because the download can hang.
        if (staleCopy) {
            RETRY_AFTER.put(cacheKey, Instant.now().plus(FAILED_REFRESH_RETRY));
        }

        try {
            String jwt = fetchTrustListJwt();
            verifySignature(jwt);
            TrustListParseResult result = parseTrustListJwt(jwt, serviceStatuses);
            currentLoTEType = result.loTEType;
            if (result.expiresAt == null) {
                return closedList(cacheKey);
            }
            Instant now = Instant.now();
            if (!now.isBefore(result.expiresAt)) {
                throw new IllegalStateException("Trust list from " + trustListUrl + " is expired: valid until "
                        + FailureDetails.relativeToNow(result.expiresAt) + ", local time " + now);
            }
            Instant effectiveExpiry = capExpiry(result.expiresAt);
            CachedTrustList refreshed = new CachedTrustList(
                    List.copyOf(result.certificates),
                    List.copyOf(result.issuanceCertificates),
                    List.copyOf(result.revocationCertificates),
                    effectiveExpiry,
                    Instant.now(),
                    result.expiresAt,
                    result.loTEType);
            CACHE.put(cacheKey, refreshed);
            RETRY_AFTER.remove(cacheKey);

            if (refreshed.certificates.isEmpty()) {
                LOG.warnf(
                        "Trust list loaded from %s contains no usable certificates (LoTE type %s), so it trusts "
                                + "nothing",
                        trustListUrl, result.loTEType);
            }
            LOG.infof(
                    "Trust list loaded from %s: %d keys (valid until %s, cache until %s)",
                    trustListUrl,
                    refreshed.certificates.size(),
                    formatInstant(result.expiresAt),
                    formatInstant(effectiveExpiry));
            return refreshed;
        } catch (Exception e) {
            if (staleCopy) {
                currentLoTEType = cached.loTEType;
                LOG.warnf(
                        e,
                        "Failed to refresh trust list from %s: %s. Using stale cache (%d keys, fetched %s, expired %s)",
                        trustListUrl,
                        FailureDetails.causeChain(e),
                        cached.certificates.size(),
                        cached.fetchedAt,
                        cached.expiresAt);
                fireRefreshFailed(true, e);
                return cached;
            }
            LOG.warnf(
                    e,
                    "Failed to fetch trust list from %s: %s. No stale copy is available, so it trusts nothing",
                    trustListUrl,
                    FailureDetails.causeChain(e));
            fireRefreshFailed(false, e);
            if (session != null) {
                session.setAttribute(UNAVAILABLE_ATTRIBUTE, Boolean.TRUE);
            }
            return CachedTrustList.empty();
        }
    }

    // Drops the cached copy as well, because a closed list expires its services (ETSI TS 119 602
    // V1.1.1 clause 6.3.15) and a stale copy must not outlive that.
    private CachedTrustList closedList(CacheKey cacheKey) {
        CACHE.remove(cacheKey);
        LOG.warnf("Trust list from %s has no NextUpdate, so it is closed and trusts nothing", trustListUrl);
        fireRefreshFailed(false, new IllegalStateException("The trust list is closed: it has no NextUpdate"));
        return CachedTrustList.empty();
    }

    // Accepts a copy until its NextUpdate, because the cache TTL expires a list long before that.
    private boolean staleCopyUsable(CachedTrustList cached) {
        Instant now = Instant.now();
        return now.isBefore(cached.validUntil)
                || (!Duration.ZERO.equals(maxStaleAge) && now.isBefore(cached.fetchedAt.plus(maxStaleAge)));
    }

    // Tells whether a list of this request had no usable copy.
    static boolean unavailableIn(KeycloakSession session) {
        return session != null && session.getAttribute(UNAVAILABLE_ATTRIBUTE) != null;
    }

    private void fireRefreshFailed(boolean staleDataInUse, Exception e) {
        Oid4vpEventService.fireOnce(
                session,
                "oid4vp.event.trust-list-failed." + cacheKey(),
                new TrustMaterialFailedEvent(
                        Oid4vpEventService.realmId(session),
                        providerId,
                        TrustMaterialFailedEvent.Failure.REFRESH_FAILED,
                        trustListUrl,
                        staleDataInUse,
                        FailureDetails.causeChain(e)));
    }

    /**
     * Returns the {@code aki} values for DCQL {@code trusted_authorities} entries.
     *
     * <p>OID4VP 1.0 section 6.1.1.1 matches an {@code aki} against the AuthorityKeyIdentifier of a
     * certificate in the credential chain. That identifier names the issuing authority, so only the
     * certificate authorities of the trust list are advertised. An end entity certificate is left out
     * because no certificate in a credential chain points at it.
     *
     * <p>The value is the Subject Key Identifier of the CA. A CA without one falls back to its AKI
     * extension, which names its own issuer. No synthetic identifier is derived, because an
     * {@code aki} value has to be the value of a certificate extension.
     */
    public List<String> getTrustedAuthorityKeyIdentifiers() {
        return authorityKeyIdentifiersOf(getIssuanceCertificates().stream()
                .filter(X5cChainValidator::isCaCertificate)
                .toList());
    }

    private List<String> authorityKeyIdentifiersOf(List<X509Certificate> certificates) {
        LinkedHashSet<String> authorityKeyIdentifiers = new LinkedHashSet<>();
        for (X509Certificate certificate : certificates) {
            String authorityKeyIdentifier = extractAuthorityKeyIdentifier(certificate);
            if (authorityKeyIdentifier != null) {
                authorityKeyIdentifiers.add(authorityKeyIdentifier);
            }
        }
        return List.copyOf(authorityKeyIdentifiers);
    }

    public String getCurrentLoTEType() {
        return currentLoTEType;
    }

    void verifySignature(String jwt) throws Exception {
        if (signingCertificates == null || signingCertificates.isEmpty()) {
            if (WARNED_UNSIGNED_TRUST_LISTS.add(cacheKey())) {
                LOG.warnf(
                        "Trust list JWT signature not verified for %s: no signing certificate configured",
                        trustListUrl);
                Oid4vpEventService.fire(
                        session,
                        new TrustMaterialFailedEvent(
                                Oid4vpEventService.realmId(session),
                                providerId,
                                TrustMaterialFailedEvent.Failure.UNSIGNED,
                                trustListUrl,
                                false,
                                "No signing certificate is configured"));
            }
            return;
        }

        try {
            X5cChainValidator.verifyJwtSignatureWithPinnedKeys(jwt, signingCertificates);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Trust list JWT from " + trustListUrl + " failed signature verification against "
                            + signingCertificates.size() + " configured signing certificates: "
                            + FailureDetails.causeChain(e),
                    e);
        }
    }

    private Instant capExpiry(Instant expiry) {
        if (maxCacheTtl != null) {
            Instant maxExpiry = Instant.now().plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    // Ignores HTTP cache headers, because the list is a signed object that states its own freshness
    // in NextUpdate. trustListMaxCacheTtlSeconds bounds how late an early reissue is noticed.
    protected String fetchTrustListJwt() throws Exception {
        if (session != null) {
            try (SimpleHttp.Response response = SimpleHttp.doGet(trustListUrl, session)
                    .connectTimeoutMillis(CONNECT_TIMEOUT_MILLIS)
                    .header("Accept", "application/jwt")
                    .asResponse()) {
                if (response.getStatus() / 100 != 2) {
                    throw new IllegalStateException("HTTP " + response.getStatus() + " fetching trust list from "
                            + trustListUrl + " (" + FailureDetails.httpResponse(response) + ")");
                }
                return response.asString();
            }
        }
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    CacheKey cacheKey() {
        return new CacheKey(
                providerId,
                trustListUrl,
                CertificateFingerprints.of(signingCertificates),
                maxCacheTtl,
                maxStaleAge,
                serviceStatuses);
    }

    static String extractAuthorityKeyIdentifier(X509Certificate certificate) {
        try {
            byte[] subjectKeyIdentifier = extractSubjectKeyIdentifier(certificate);
            if (subjectKeyIdentifier != null && subjectKeyIdentifier.length > 0) {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(subjectKeyIdentifier);
            }

            byte[] authorityKeyIdentifier = extractAuthorityKeyIdentifierBytes(certificate);
            if (authorityKeyIdentifier != null && authorityKeyIdentifier.length > 0) {
                return Base64.getUrlEncoder().withoutPadding().encodeToString(authorityKeyIdentifier);
            }

            return null;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract authority key identifier from certificate", e);
        }
    }

    private static byte[] extractSubjectKeyIdentifier(X509Certificate certificate) throws Exception {
        byte[] extension = certificate.getExtensionValue("2.5.29.14");
        if (extension == null) {
            return null;
        }
        return unwrapDerOctetString(unwrapDerOctetString(extension));
    }

    private static byte[] extractAuthorityKeyIdentifierBytes(X509Certificate certificate) throws Exception {
        byte[] extension = certificate.getExtensionValue("2.5.29.35");
        if (extension == null) {
            return null;
        }
        byte[] authorityKeyIdentifier = unwrapDerOctetString(extension);
        DerValue sequence = readDerValue(authorityKeyIdentifier, 0);
        if (sequence.tag() != 0x30) {
            throw new IllegalStateException("AuthorityKeyIdentifier extension is not a DER sequence");
        }

        int offset = 0;
        while (offset < sequence.value().length) {
            DerValue value = readDerValue(sequence.value(), offset);
            if (value.tag() == 0x80) {
                return value.value();
            }
            offset += value.totalLength();
        }
        return null;
    }

    private static byte[] unwrapDerOctetString(byte[] der) {
        DerValue octetString = readDerValue(der, 0);
        if (octetString.tag() != 0x04) {
            throw new IllegalStateException("Expected DER OCTET STRING");
        }
        return octetString.value();
    }

    private static DerValue readDerValue(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalStateException("Invalid DER input");
        }

        int tag = der[offset] & 0xFF;
        if (offset + 1 >= der.length) {
            throw new IllegalStateException("Invalid DER length");
        }

        int lengthByte = der[offset + 1] & 0xFF;
        int length;
        int lengthBytes = 1;
        if ((lengthByte & 0x80) == 0) {
            length = lengthByte;
        } else {
            int lengthOctets = lengthByte & 0x7F;
            if (lengthOctets == 0 || lengthOctets > 4 || offset + 2 + lengthOctets > der.length) {
                throw new IllegalStateException("Unsupported DER length encoding");
            }
            length = 0;
            for (int i = 0; i < lengthOctets; i++) {
                length = (length << 8) | (der[offset + 2 + i] & 0xFF);
            }
            lengthBytes += lengthOctets;
        }

        int valueOffset = offset + 1 + lengthBytes;
        int end = valueOffset + length;
        if (end > der.length) {
            throw new IllegalStateException("Invalid DER value length");
        }

        byte[] value = new byte[length];
        System.arraycopy(der, valueOffset, value, 0, length);
        return new DerValue(tag, value, 1 + lengthBytes + length);
    }

    private record DerValue(int tag, byte[] value, int totalLength) {}

    static TrustListParseResult parseTrustListJwt(String jwt, List<String> serviceStatuses) throws Exception {
        JWSInput parsedJwt = X5cChainValidator.parseJwt(jwt);
        TrustListJwt trustList = parseTrustListClaims(X5cChainValidator.parseClaims(parsedJwt));
        Instant expiresAt = parseLoTEInstant(trustList.nextUpdate());
        List<X509Certificate> certificates = new ArrayList<>();
        List<X509Certificate> issuanceCertificates = new ArrayList<>();
        List<X509Certificate> revocationCertificates = new ArrayList<>();
        for (TrustedEntity entity : trustList.trustedEntities()) {
            if (entity != null) {
                addEntityCertificates(
                        entity, serviceStatuses, certificates, issuanceCertificates, revocationCertificates);
            }
        }

        return new TrustListParseResult(
                List.copyOf(certificates),
                List.copyOf(issuanceCertificates),
                List.copyOf(revocationCertificates),
                expiresAt,
                trustList.loTEType());
    }

    @SuppressWarnings("unchecked")
    private static TrustListJwt parseTrustListClaims(Map<String, Object> claims) {
        Object loTE = claims.get("LoTE");
        if (!(loTE instanceof Map<?, ?> wrappedClaims)) {
            throw new IllegalStateException("Trust list JWT payload must contain top-level LoTE object");
        }
        return JsonSerialization.mapper.convertValue((Map<String, Object>) wrappedClaims, TrustListJwt.class);
    }

    private static void addEntityCertificates(
            TrustedEntity entity,
            List<String> serviceStatuses,
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates) {
        for (TrustedEntityService service : entity.services()) {
            if (service == null || service.serviceInformation() == null) {
                continue;
            }
            var serviceInformation = service.serviceInformation();
            // Trusts a service without a status, because most LoTE profiles forbid the component
            // (ETSI TS 119 602 V1.1.1 Annex H). A status counts only when the admin lists it.
            String status = serviceInformation.serviceStatus();
            if (status != null && !serviceStatuses.contains(status)) {
                continue;
            }
            ServiceDigitalIdentity digitalIdentity = serviceInformation.serviceDigitalIdentity();
            if (digitalIdentity != null) {
                List<X509Certificate> parsed = parseCertificates(digitalIdentity.x509Certificates());
                certificates.addAll(parsed);
                if (isIssuanceService(serviceInformation.serviceTypeIdentifier())) {
                    issuanceCertificates.addAll(parsed);
                }
                if (isRevocationService(serviceInformation.serviceTypeIdentifier())) {
                    revocationCertificates.addAll(parsed);
                }
            }
        }
    }

    private static List<X509Certificate> parseCertificates(List<X509CertificateEntry> x509Certs) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateEntry certEntry : x509Certs) {
            if (certEntry != null && certEntry.value() != null) {
                addCertificate(certEntry.value(), certificates);
            }
        }
        return certificates;
    }

    private static boolean isIssuanceService(String serviceTypeIdentifier) {
        return serviceTypeIdentifier != null && serviceTypeIdentifier.endsWith(SERVICE_TYPE_SUFFIX_ISSUANCE);
    }

    private static boolean isRevocationService(String serviceTypeIdentifier) {
        return serviceTypeIdentifier != null && serviceTypeIdentifier.endsWith(SERVICE_TYPE_SUFFIX_REVOCATION);
    }

    private static void addCertificate(Object value, List<X509Certificate> certificates) {
        try {
            byte[] certDer = Base64.getMimeDecoder().decode(value.toString());
            X509Certificate cert = (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certDer));
            certificates.add(cert);
            LOG.debugf(
                    "Loaded trusted certificate: %s",
                    cert.getSubjectX500Principal().getName());
        } catch (Exception e) {
            LOG.warnf("Failed to parse certificate from trust list: %s", e.getMessage());
        }
    }

    /**
     * Reads a LoTE date-time such as {@code NextUpdate}. ETSI TS 119 602 V1.1.1 clause 6.1.3 requires
     * an ISO 8601 UTC string with "year with four digits, month, day, hour, minute, second (without
     * decimal fraction) and the UTC designator 'Z'". {@link Instant#parse} reads those, and also
     * accepts fractional seconds and numeric offsets. A value without seconds fails to parse and
     * rejects the whole list. {@code NextUpdate} is the freshness the list promises, so reading an
     * unparseable value as absent would turn a long expired list into one that never expires.
     *
     * @see <a href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf">ETSI TS 119 602 V1.1.1 clause 6.1.3, Date-time indication</a>
     */
    private static Instant parseLoTEInstant(String value) {
        if (value == null || value.isBlank() || "null".equalsIgnoreCase(value)) {
            return null;
        }
        return Instant.parse(value);
    }

    private static String formatInstant(Instant instant) {
        return instant != null ? instant.toString() : "none";
    }

    // Exists for tests only.
    static void clearCache() {
        CACHE.clear();
        RETRY_AFTER.clear();
    }

    // Exists for tests of the stale cache fallback.
    static void seedExpiredCache(
            TrustListProvider provider, List<X509Certificate> certificates, Instant expiredAt, Instant fetchedAt) {
        seedExpiredCache(provider, certificates, expiredAt, fetchedAt, expiredAt);
    }

    static void seedExpiredCache(
            TrustListProvider provider,
            List<X509Certificate> certificates,
            Instant expiredAt,
            Instant fetchedAt,
            Instant validUntil) {
        CACHE.put(
                provider.cacheKey(),
                new CachedTrustList(
                        certificates,
                        certificates,
                        certificates,
                        expiredAt,
                        fetchedAt,
                        validUntil,
                        provider.currentLoTEType));
    }

    record TrustListParseResult(
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates,
            Instant expiresAt,
            String loTEType) {}

    record CacheKey(
            String providerId,
            String trustListUrl,
            List<String> signingCertificateFingerprints,
            Duration maxCacheTtl,
            Duration maxStaleAge,
            List<String> serviceStatuses) {}

    private record CachedTrustList(
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates,
            Instant expiresAt,
            Instant fetchedAt,
            Instant validUntil,
            String loTEType) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }

        static CachedTrustList empty() {
            return new CachedTrustList(List.of(), List.of(), List.of(), Instant.EPOCH, Instant.EPOCH, null, null);
        }
    }
}
