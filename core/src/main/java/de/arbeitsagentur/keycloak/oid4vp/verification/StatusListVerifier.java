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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.util.BoundedLruMap;
import de.arbeitsagentur.keycloak.oid4vp.util.CertificateFingerprints;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;

/**
 * Verifies credential revocation status using Token Status List (draft-ietf-oauth-status-list). A
 * credential may carry a {@code status.status_list} claim with a {@code uri} and an {@code idx},
 * where the URI points to a JWT whose payload holds a DEFLATE-compressed bitstring, and a non-zero
 * value at the credential's index means the credential is revoked.
 */
public class StatusListVerifier {

    private static final Logger LOG = Logger.getLogger(StatusListVerifier.class);
    private static final int DEFAULT_BITS_PER_STATUS = 1;
    private static final int MAX_CACHE_ENTRIES = 256;
    private static final int MAX_INFLATED_BYTES = 16 * 1024 * 1024;

    /**
     * Decoded status lists, keyed by their URI and by the trust material they are verified against,
     * so that a list one trust domain accepted is never reused for a credential whose trust domain
     * judges status list signatures by other certificates.
     */
    private static final Map<CacheKey, CachedStatusList> CACHE = BoundedLruMap.withMaxEntries(MAX_CACHE_ENTRIES);

    private final KeycloakSession session;
    private final Duration maxCacheTtl;

    StatusListVerifier() {
        this(null, null);
    }

    public StatusListVerifier(KeycloakSession session, Duration maxCacheTtl) {
        this.session = session;
        this.maxCacheTtl = maxCacheTtl;
    }

    /** Checks the revocation status without revocation trust material, leaving the status list JWT unverified. */
    void checkRevocationStatus(Map<String, Object> claims) {
        checkRevocationStatus(claims, List.of());
    }

    /**
     * Checks the revocation status of a credential from its payload claims, returning silently when
     * the credential carries no status claim.
     *
     * @param revocationCertificates the status list service certificates of the trust domain serving
     *                               this credential. An empty list leaves the status list JWT
     *                               signature unverified.
     * @throws IllegalStateException if the credential is revoked or status check fails
     */
    public void checkRevocationStatus(Map<String, Object> claims, List<X509Certificate> revocationCertificates) {
        StatusReference ref = extractStatusReference(claims);
        if (ref == null) {
            LOG.debug("No status_list claim found in credential — skipping revocation check");
            return;
        }

        // The status list draft requires an https uri. Nothing but TLS says who answers there.
        if (!ref.uri.regionMatches(true, 0, "https://", 0, 8)) {
            throw new IllegalStateException("Status list URI '" + ref.uri + "' is not an https URL");
        }
        LOG.infof("Checking revocation status: uri=%s, idx=%d", ref.uri, ref.idx);

        try {
            DecodedStatusList statusList = fetchAndDecodeStatusList(ref.uri, revocationCertificates);
            int status = getStatusAtIndex(statusList.statusBits, ref.idx, statusList.bitsPerStatus);

            if (status != 0) {
                throw new IllegalStateException(
                        "Credential has been revoked (status=" + status + " at index " + ref.idx + ")");
            }

            LOG.infof("Revocation check passed: status=%d at index %d", status, ref.idx);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.warnf(e, "Failed to check revocation status from %s", ref.uri);
            throw new IllegalStateException(
                    "Unable to verify credential revocation status from " + ref.uri + ": " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    StatusReference extractStatusReference(Map<String, Object> claims) {
        if (claims == null) return null;

        Object statusObj = claims.get("status");
        if (statusObj == null) {
            statusObj = findNestedStatusClaim(claims);
        }

        if (!(statusObj instanceof Map<?, ?> statusMap)) return null;

        Object statusListObj = statusMap.get("status_list");
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) return null;

        Object uriObj = statusListMap.get("uri");
        Object idxObj = statusListMap.get("idx");
        if (uriObj == null || idxObj == null) return null;

        String uri = stringValue(uriObj);
        Integer idx = integerValue(idxObj);
        if (uri == null || idx == null) return null;
        return new StatusReference(uri, idx);
    }

    private Object findNestedStatusClaim(Map<String, Object> claims) {
        for (Object value : claims.values()) {
            if (value instanceof Map<?, ?> namespaceClaims) {
                Object status = namespaceClaims.get("status");
                if (status != null) {
                    return status;
                }
            }
        }
        return null;
    }

    DecodedStatusList fetchAndDecodeStatusList(String uri, List<X509Certificate> revocationCertificates)
            throws Exception {
        CacheKey cacheKey = cacheKey(uri, revocationCertificates);
        CachedStatusList cached = CACHE.get(cacheKey);
        if (cached != null && cached.isValid()) {
            LOG.debugf("Using cached status list for %s (expires %s)", uri, cached.expiresAt);
            return cached.decoded;
        }

        String jwt = fetchStatusListJwt(uri);
        JWSInput signedJwt = X5cChainValidator.parseJwt(jwt);
        Map<String, Object> claims = X5cChainValidator.parseClaims(signedJwt);

        verifyStatusListJwtSignature(jwt, claims, revocationCertificates);

        validateStatusListToken(headerType(signedJwt), stringClaim(claims, "sub"), instantClaim(claims, "exp"), uri);
        Map<String, Object> statusListClaim = jsonObjectClaim(claims, "status_list");
        if (statusListClaim == null) {
            throw new IllegalStateException("Status list JWT missing status_list claim");
        }

        Object lstObj = statusListClaim.get("lst");
        if (!(lstObj instanceof String lst)) {
            throw new IllegalStateException("Status list JWT missing status_list.lst claim");
        }

        int bitsPerStatus = DEFAULT_BITS_PER_STATUS;
        Object bitsObj = statusListClaim.get("bits");
        if (bitsObj instanceof Number num) {
            bitsPerStatus = num.intValue();
        }
        validateBitsPerStatus(bitsPerStatus);

        byte[] compressed = Base64.getUrlDecoder().decode(lst);
        byte[] statusBits = inflate(compressed);

        Instant expiresAt = resolveExpiry(instantClaim(claims, "exp"), claims.get("ttl"));

        var decoded = new DecodedStatusList(statusBits, bitsPerStatus);
        CACHE.put(cacheKey, new CachedStatusList(decoded, expiresAt));
        return decoded;
    }

    private CacheKey cacheKey(String uri, List<X509Certificate> revocationCertificates) {
        return new CacheKey(uri, CertificateFingerprints.of(revocationCertificates), maxCacheTtl);
    }

    private void verifyStatusListJwtSignature(
            String compactJwt, Map<String, Object> claims, List<X509Certificate> revocationCertificates)
            throws Exception {
        List<X509Certificate> trustedCerts = revocationCertificates != null ? revocationCertificates : List.of();
        if (trustedCerts.isEmpty()) {
            LOG.debugf(
                    "Status list JWT signature not verified: no trusted keys configured (issuer=%s)",
                    stringClaim(claims, "iss"));
            return;
        }

        X5cChainValidator.verifyJwtSignature(compactJwt, trustedCerts);
    }

    /**
     * Validates the Status List Token header and claims per draft-ietf-oauth-status-list Section 5.1
     * and Section 8.3.
     */
    void validateStatusListToken(String typ, String sub, Instant exp, String expectedUri) {
        if (!"statuslist+jwt".equals(typ)) {
            throw new IllegalStateException(
                    "Status list JWT has invalid typ header: expected 'statuslist+jwt', got '" + typ + "'");
        }

        if (!expectedUri.equals(sub)) {
            throw new IllegalStateException(
                    "Status list JWT sub claim '" + sub + "' does not match expected URI '" + expectedUri + "'");
        }

        if (exp != null && exp.isBefore(Instant.now())) {
            throw new IllegalStateException("Status list JWT has expired");
        }
    }

    /**
     * Resolves the cache expiry for a Status List Token from {@code ttl} (seconds from fetch time),
     * falling back to {@code exp}, capped at {@code maxCacheTtl} when one is configured.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list">Section 13.7</a>
     */
    Instant resolveExpiry(Instant exp, Object ttlObj) {
        Instant now = Instant.now();
        Instant expiry;

        if (ttlObj instanceof Number ttlNum && ttlNum.longValue() > 0) {
            Instant ttlExpiry = now.plusSeconds(ttlNum.longValue());
            expiry = (exp != null && exp.isBefore(ttlExpiry)) ? exp : ttlExpiry;
        } else if (exp != null) {
            expiry = exp;
        } else {
            expiry = now;
        }

        if (maxCacheTtl != null) {
            Instant maxExpiry = now.plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    String fetchStatusListJwt(String uri) throws Exception {
        if (session != null) {
            try (SimpleHttp.Response response = SimpleHttp.doGet(uri, session)
                    .header("Accept", "application/statuslist+jwt")
                    .asResponse()) {
                if (response.getStatus() / 100 != 2) {
                    throw new IllegalStateException(
                            "HTTP " + response.getStatus() + " fetching status list from " + uri);
                }
                return response.asString();
            }
        }
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    static byte[] inflate(byte[] compressed) throws Exception {
        try (var is = new InflaterInputStream(new ByteArrayInputStream(compressed))) {
            return readBounded(is);
        } catch (IOException e) {
            // Retry as raw DEFLATE without a zlib header. Only format errors reach this retry,
            // because a list over the size bound throws IllegalStateException and is never inflated
            // a second time.
            Inflater rawInflater = new Inflater(true);
            try (var is = new InflaterInputStream(new ByteArrayInputStream(compressed), rawInflater)) {
                return readBounded(is);
            } finally {
                rawInflater.end();
            }
        }
    }

    /**
     * Reads the inflated bytes under a size bound, so a DEFLATE bomb served as a status list cannot
     * exhaust the heap.
     */
    private static byte[] readBounded(InflaterInputStream is) throws IOException {
        byte[] data = is.readNBytes(MAX_INFLATED_BYTES);
        if (is.read() != -1) {
            throw new IllegalStateException("Status list exceeds " + MAX_INFLATED_BYTES + " bytes after decompression");
        }
        return data;
    }

    static int getStatusAtIndex(byte[] statusBits, int idx, int bitsPerStatus) {
        if (statusBits == null || statusBits.length == 0) {
            throw new IllegalStateException("Empty status list");
        }
        validateBitsPerStatus(bitsPerStatus);
        int bitOffset = idx * bitsPerStatus;
        int byteIndex = bitOffset / 8;
        int bitIndex = bitOffset % 8;

        if (byteIndex >= statusBits.length) {
            throw new IllegalStateException("Status index " + idx + " out of range (list has "
                    + (statusBits.length * 8 / bitsPerStatus) + " entries)");
        }

        int mask = ((1 << bitsPerStatus) - 1);
        int byteValue = Byte.toUnsignedInt(statusBits[byteIndex]);
        return (byteValue >>> bitIndex) & mask;
    }

    private static void validateBitsPerStatus(int bitsPerStatus) {
        if (bitsPerStatus != 1 && bitsPerStatus != 2 && bitsPerStatus != 4 && bitsPerStatus != 8) {
            throw new IllegalArgumentException("bitsPerStatus must be one of 1, 2, 4, or 8, got " + bitsPerStatus);
        }
    }

    /** Clears the static cache, for tests only. */
    static void clearCache() {
        CACHE.clear();
    }

    record CacheKey(String uri, List<String> revocationCertificateFingerprints, Duration maxCacheTtl) {}

    record StatusReference(String uri, int idx) {}

    record DecodedStatusList(byte[] statusBits, int bitsPerStatus) {}

    private record CachedStatusList(DecodedStatusList decoded, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }

    private String headerType(JWSInput jwt) {
        return jwt.getHeader().getType();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonObjectClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
    }

    private String stringClaim(Map<String, Object> claims, String name) {
        return stringValue(claims.get(name));
    }

    private Instant instantClaim(Map<String, Object> claims, String name) {
        Long epochSeconds = longValue(claims.get(name));
        if (epochSeconds != null) {
            return Instant.ofEpochSecond(epochSeconds);
        }
        return null;
    }

    private String stringValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof JsonNode jsonNode) {
            return jsonNode.isTextual() ? jsonNode.textValue() : null;
        }
        return value.toString();
    }

    private Integer integerValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        Long longValue = longValue(value);
        if (longValue == null) {
            return null;
        }
        try {
            return Math.toIntExact(longValue);
        } catch (ArithmeticException e) {
            return null;
        }
    }

    private Long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof JsonNode jsonNode) {
            if (jsonNode.isIntegralNumber()) {
                return jsonNode.longValue();
            }
            if (jsonNode.isTextual()) {
                try {
                    return Long.parseLong(jsonNode.textValue());
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            return null;
        }
        if (value != null) {
            try {
                return Long.parseLong(value.toString());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
