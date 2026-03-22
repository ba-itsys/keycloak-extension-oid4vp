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

import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.ServiceDigitalIdentity;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustListJwt;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustedEntity;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.TrustedEntityService;
import de.arbeitsagentur.keycloak.oid4vp.verification.trustlist.X509CertificateEntry;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * Fetches and caches an ETSI TS 119 602 trust list JWT from a configured URL.
 * Extracts X.509 issuer certificates and their public keys for credential verification.
 *
 * <p>When a signing certificate is configured, the trust list JWT signature is verified before
 * extracting certificates. Without a signing certificate, the JWT is accepted without signature
 * verification and a warning should be surfaced by configuration handling.
 */
public class TrustListProvider {

    private static final Logger LOG = Logger.getLogger(TrustListProvider.class);
    private static final ConcurrentHashMap<CacheKey, CachedTrustList> CACHE = new ConcurrentHashMap<>();
    private static final Set<String> WARNED_UNSIGNED_TRUST_LISTS = ConcurrentHashMap.newKeySet();
    static final Duration DEFAULT_MAX_STALE_AGE = Duration.ofDays(1);
    private static final String SERVICE_TYPE_SUFFIX_ISSUANCE = "/Issuance";
    private static final String SERVICE_TYPE_SUFFIX_REVOCATION = "/Revocation";

    private final KeycloakSession session;
    private final String trustListUrl;
    private final List<X509Certificate> staticCertificates;
    private final Duration maxCacheTtl;
    private final Duration maxStaleAge;
    private final List<X509Certificate> signingCertificates;
    private volatile String currentLoTEType;

    /** Creates a provider that fetches the trust list from the given URL. */
    public TrustListProvider(KeycloakSession session, String trustListUrl) {
        this(session, trustListUrl, null, null, null);
    }

    /** Creates a provider that fetches the trust list from the given URL with a cache TTL cap. */
    public TrustListProvider(KeycloakSession session, String trustListUrl, Duration maxCacheTtl) {
        this(session, trustListUrl, maxCacheTtl, null, null);
    }

    /**
     * Creates a provider that fetches the trust list from the given URL with a cache TTL cap
     * and optional signature verification.
     *
     * @param signingCertificates if non-null/non-empty, the trust list JWT signature is verified.
     *     The JWT's x5c chain is validated against these certificates, or the JWT signature is
     *     verified directly against each certificate's public key.
     */
    public TrustListProvider(
            KeycloakSession session,
            String trustListUrl,
            Duration maxCacheTtl,
            List<X509Certificate> signingCertificates) {
        this(session, trustListUrl, maxCacheTtl, null, signingCertificates);
    }

    /**
     * Creates a provider with full configuration.
     *
     * @param maxStaleAge maximum age of a stale (expired) cache entry that can be used as fallback
     *     when a trust list refresh fails. If {@code null}, defaults to 1 day. Set to
     *     {@link Duration#ZERO} to disable stale cache usage entirely.
     */
    public TrustListProvider(
            KeycloakSession session,
            String trustListUrl,
            Duration maxCacheTtl,
            Duration maxStaleAge,
            List<X509Certificate> signingCertificates) {
        this.session = session;
        this.trustListUrl = trustListUrl;
        this.staticCertificates = null;
        this.maxCacheTtl = maxCacheTtl;
        this.maxStaleAge = maxStaleAge != null ? maxStaleAge : DEFAULT_MAX_STALE_AGE;
        this.signingCertificates = signingCertificates;
    }

    /** Creates a provider with static trusted certificates. Useful for testing. */
    public TrustListProvider(List<X509Certificate> staticCertificates) {
        this.session = null;
        this.trustListUrl = null;
        this.staticCertificates = staticCertificates != null ? List.copyOf(staticCertificates) : null;
        this.maxCacheTtl = null;
        this.maxStaleAge = DEFAULT_MAX_STALE_AGE;
        this.signingCertificates = null;
    }

    /**
     * Returns trusted public keys from the configured trust list.
     * Results are cached based on trust-list freshness metadata.
     */
    public List<PublicKey> getTrustedKeys() {
        return getTrustedCertificates().stream()
                .map(X509Certificate::getPublicKey)
                .toList();
    }

    /** Returns X.509 certificates from issuance services in the configured trust list. */
    public List<X509Certificate> getIssuanceCertificates() {
        if (staticCertificates != null) {
            return staticCertificates;
        }
        return getTrustedTrustList().issuanceCertificates();
    }

    /** Returns X.509 certificates from revocation services in the configured trust list. */
    public List<X509Certificate> getRevocationCertificates() {
        if (staticCertificates != null) {
            return staticCertificates;
        }
        return getTrustedTrustList().revocationCertificates();
    }

    /**
     * Returns trusted X.509 certificates from the configured trust list.
     * Results are cached based on trust-list freshness metadata.
     */
    public List<X509Certificate> getTrustedCertificates() {
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

        try {
            FetchedTrustList fetched = fetchTrustListJwt();
            verifySignature(fetched.jwt());
            TrustListParseResult result = parseTrustListJwt(fetched.jwt());
            currentLoTEType = result.loTEType;
            Instant now = Instant.now();
            if (result.expiresAt != null && !now.isBefore(result.expiresAt)) {
                throw new IllegalStateException("Trust list is expired at " + formatInstant(result.expiresAt));
            }
            Instant effectiveExpiry = capExpiry(earliestInstant(result.expiresAt, fetched.httpCacheExpiresAt()));
            CachedTrustList refreshed = new CachedTrustList(
                    List.copyOf(result.certificates),
                    List.copyOf(result.issuanceCertificates),
                    List.copyOf(result.revocationCertificates),
                    effectiveExpiry,
                    Instant.now(),
                    result.loTEType);
            if (effectiveExpiry != null) {
                CACHE.put(cacheKey, refreshed);
            }

            LOG.infof(
                    "Trust list loaded from %s: %d keys (valid until %s, cache until %s)",
                    trustListUrl,
                    refreshed.certificates.size(),
                    formatInstant(result.expiresAt),
                    formatInstant(effectiveExpiry));
            return refreshed;
        } catch (Exception e) {
            if (cached != null
                    && !cached.certificates.isEmpty()
                    && !Duration.ZERO.equals(maxStaleAge)
                    && Instant.now().isBefore(cached.fetchedAt.plus(maxStaleAge))) {
                currentLoTEType = cached.loTEType;
                LOG.warnf(
                        "Failed to refresh trust list from %s: %s — using stale cache (%d keys, fetched %s, expired %s)",
                        trustListUrl, e.getMessage(), cached.certificates.size(), cached.fetchedAt, cached.expiresAt);
                return cached;
            }
            LOG.warnf("Failed to fetch trust list from %s: %s", trustListUrl, e.getMessage());
            return CachedTrustList.empty();
        }
    }

    /**
     * Returns trusted authority key identifiers for DCQL {@code trusted_authorities} entries.
     *
     * <p>The preferred identifier is the authority certificate's Subject Key Identifier because
     * credential-chain AKI values normally point to that identifier. If SKI is absent, fall back
     * to an explicit AKI extension. No synthetic identifier is derived because OID4VP/HAIP
     * `aki` values are meant to represent certificate extension values.
     */
    public List<String> getTrustedAuthorityKeyIdentifiers() {
        LinkedHashSet<String> authorityKeyIdentifiers = new LinkedHashSet<>();
        for (X509Certificate certificate : getIssuanceCertificates()) {
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
            if (WARNED_UNSIGNED_TRUST_LISTS.add(trustListUrl)) {
                LOG.warnf(
                        "Trust list JWT signature not verified for %s: no signing certificate configured",
                        trustListUrl);
            }
            return;
        }

        X5cChainValidator.verifyJwtSignature(jwt, signingCertificates);
    }

    private Instant capExpiry(Instant expiry) {
        if (expiry == null) {
            return null;
        }
        if (maxCacheTtl != null) {
            Instant maxExpiry = Instant.now().plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    protected FetchedTrustList fetchTrustListJwt() throws Exception {
        if (session != null) {
            try (SimpleHttp.Response response = SimpleHttp.doGet(trustListUrl, session)
                    .header("Accept", "application/jwt")
                    .asResponse()) {
                return new FetchedTrustList(response.asString(), resolveHttpCacheExpiry(response));
            }
        }
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    CacheKey cacheKey() {
        return new CacheKey(trustListUrl, fingerprintCertificates(signingCertificates), maxCacheTtl, maxStaleAge);
    }

    private static List<String> fingerprintCertificates(List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return List.of();
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(JavaAlgorithm.SHA256);
            return certificates.stream()
                    .map(cert -> fingerprintCertificate(cert, digest))
                    .sorted()
                    .toList();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint trust list signing certificates", e);
        }
    }

    private static String fingerprintCertificate(X509Certificate certificate, MessageDigest digest) {
        try {
            byte[] encoded = digest.digest(certificate.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint trust list signing certificate", e);
        }
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

    static TrustListParseResult parseTrustListJwt(String jwt) throws Exception {
        JWSInput parsedJwt = X5cChainValidator.parseJwt(jwt);
        TrustListJwt trustList =
                JsonSerialization.mapper.convertValue(X5cChainValidator.parseClaims(parsedJwt), TrustListJwt.class);
        Instant expiresAt = parseLoTEInstant(trustList.nextUpdate());
        List<X509Certificate> certificates = new ArrayList<>();
        List<X509Certificate> issuanceCertificates = new ArrayList<>();
        List<X509Certificate> revocationCertificates = new ArrayList<>();
        for (TrustedEntity entity : trustList.trustedEntities()) {
            if (entity != null) {
                addEntityCertificates(entity, certificates, issuanceCertificates, revocationCertificates);
            }
        }

        return new TrustListParseResult(
                List.copyOf(certificates),
                List.copyOf(issuanceCertificates),
                List.copyOf(revocationCertificates),
                expiresAt,
                trustList.loTEType());
    }

    private static void addEntityCertificates(
            TrustedEntity entity,
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates) {
        for (TrustedEntityService service : entity.services()) {
            if (service == null || service.serviceInformation() == null) {
                continue;
            }
            var serviceInformation = service.serviceInformation();
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

    private static Instant parseLoTEInstant(String value) {
        if (value == null || value.isBlank() || "null".equalsIgnoreCase(value)) {
            return null;
        }
        return Instant.parse(value);
    }

    private static Instant resolveHttpCacheExpiry(SimpleHttp.Response response) throws Exception {
        Instant now = Instant.now();
        String cacheControl = response.getFirstHeader("Cache-Control");
        if (cacheControl != null) {
            for (String directive : cacheControl.split(",")) {
                String trimmed = directive.trim().toLowerCase(Locale.ROOT);
                if ("no-store".equals(trimmed) || "no-cache".equals(trimmed) || "max-age=0".equals(trimmed)) {
                    return now;
                }
                if (trimmed.startsWith("max-age=")) {
                    try {
                        long maxAgeSeconds = Long.parseLong(trimmed.substring("max-age=".length()));
                        return now.plusSeconds(Math.max(0, maxAgeSeconds));
                    } catch (NumberFormatException ignored) {
                        // Ignore malformed max-age and fall back to Expires.
                    }
                }
            }
        }

        String expires = response.getFirstHeader("Expires");
        if (expires == null || expires.isBlank()) {
            return null;
        }
        return ZonedDateTime.parse(expires, DateTimeFormatter.RFC_1123_DATE_TIME)
                .withZoneSameInstant(ZoneOffset.UTC)
                .toInstant();
    }

    private static Instant earliestInstant(Instant first, Instant second) {
        if (first == null) return second;
        if (second == null) return first;
        return first.isBefore(second) ? first : second;
    }

    private static String formatInstant(Instant instant) {
        return instant != null ? instant.toString() : "none";
    }

    /** Clears the static cache. Intended for testing only. */
    static void clearCache() {
        CACHE.clear();
    }

    /** Seeds the cache with an already-expired entry. Intended for testing stale cache fallback. */
    static void seedExpiredCache(
            TrustListProvider provider, List<X509Certificate> certificates, Instant expiredAt, Instant fetchedAt) {
        seedExpiredCache(provider, certificates, expiredAt, fetchedAt, provider.currentLoTEType);
    }

    /** Seeds the cache with an already-expired entry including LoTE metadata. Intended for testing only. */
    static void seedExpiredCache(
            TrustListProvider provider,
            List<X509Certificate> certificates,
            Instant expiredAt,
            Instant fetchedAt,
            String loTEType) {
        CACHE.put(
                provider.cacheKey(),
                new CachedTrustList(certificates, certificates, certificates, expiredAt, fetchedAt, loTEType));
    }

    record TrustListParseResult(
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates,
            Instant expiresAt,
            String loTEType) {}

    record FetchedTrustList(String jwt, Instant httpCacheExpiresAt) {}

    record CacheKey(
            String trustListUrl,
            List<String> signingCertificateFingerprints,
            Duration maxCacheTtl,
            Duration maxStaleAge) {}

    private record CachedTrustList(
            List<X509Certificate> certificates,
            List<X509Certificate> issuanceCertificates,
            List<X509Certificate> revocationCertificates,
            Instant expiresAt,
            Instant fetchedAt,
            String loTEType) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }

        static CachedTrustList empty() {
            return new CachedTrustList(List.of(), List.of(), List.of(), Instant.EPOCH, Instant.EPOCH, null);
        }
    }
}
