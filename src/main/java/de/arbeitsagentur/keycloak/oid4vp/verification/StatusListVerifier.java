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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Verifies credential revocation status using Token Status List (draft-ietf-oauth-status-list).
 *
 * <p>Credentials may contain a {@code status.status_list} claim with {@code uri} and {@code idx}.
 * The URI points to a JWT whose payload contains a DEFLATE-compressed bitstring.
 * A non-zero value at the credential's index means the credential is revoked.
 */
public class StatusListVerifier {

    private static final Logger LOG = Logger.getLogger(StatusListVerifier.class);
    private static final int DEFAULT_BITS_PER_STATUS = 1;
    private static final ConcurrentHashMap<String, CachedStatusList> CACHE = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final TrustListProvider trustListProvider;
    private final Duration maxCacheTtl;

    public StatusListVerifier() {
        this(null, null);
    }

    public StatusListVerifier(KeycloakSession session, TrustListProvider trustListProvider) {
        this(session, trustListProvider, null);
    }

    public StatusListVerifier(KeycloakSession session, TrustListProvider trustListProvider, Duration maxCacheTtl) {
        this.session = session;
        this.trustListProvider = trustListProvider;
        this.maxCacheTtl = maxCacheTtl;
    }

    /**
     * Checks the revocation status of a credential based on its payload claims.
     * If no status claim is present, this method returns silently.
     *
     * @throws IllegalStateException if the credential is revoked or status check fails
     */
    public void checkRevocationStatus(Map<String, Object> claims) {
        StatusReference ref = extractStatusReference(claims);
        if (ref == null) {
            LOG.debug("No status_list claim found in credential — skipping revocation check");
            return;
        }

        LOG.infof("Checking revocation status: uri=%s, idx=%d", ref.uri, ref.idx);

        try {
            DecodedStatusList statusList = fetchAndDecodeStatusList(ref.uri);
            int status = getStatusAtIndex(statusList.statusBits, ref.idx, statusList.bitsPerStatus);

            if (status != 0) {
                throw new IllegalStateException(
                        "Credential has been revoked (status=" + status + " at index " + ref.idx + ")");
            }

            LOG.infof("Revocation check passed: status=%d at index %d", status, ref.idx);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            LOG.warnf("Failed to check revocation status from %s: %s", ref.uri, e.getMessage());
            throw new IllegalStateException("Unable to verify credential revocation status: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    StatusReference extractStatusReference(Map<String, Object> claims) {
        if (claims == null) return null;

        Object statusObj = claims.get("status");
        if (statusObj == null) {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                if (entry.getKey().endsWith("/status")) {
                    statusObj = entry.getValue();
                    break;
                }
            }
        }

        if (!(statusObj instanceof Map<?, ?> statusMap)) return null;

        Object statusListObj = statusMap.get("status_list");
        if (!(statusListObj instanceof Map<?, ?> statusListMap)) return null;

        Object uriObj = statusListMap.get("uri");
        Object idxObj = statusListMap.get("idx");
        if (uriObj == null || idxObj == null) return null;

        String uri = uriObj.toString();
        int idx;
        if (idxObj instanceof Number num) {
            idx = num.intValue();
        } else {
            try {
                idx = Integer.parseInt(idxObj.toString());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return new StatusReference(uri, idx);
    }

    DecodedStatusList fetchAndDecodeStatusList(String uri) throws Exception {
        CachedStatusList cached = CACHE.get(uri);
        if (cached != null && cached.isValid()) {
            LOG.debugf("Using cached status list for %s (expires %s)", uri, cached.expiresAt);
            return cached.decoded;
        }

        String jwt = fetchStatusListJwt(uri);
        SignedJWT signedJWT = SignedJWT.parse(jwt);

        verifyStatusListJwtSignature(signedJWT);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        Map<String, Object> statusListClaim = claimsSet.getJSONObjectClaim("status_list");
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

        byte[] compressed = Base64.getUrlDecoder().decode(lst);
        byte[] statusBits = inflate(compressed);

        Instant expiresAt = resolveExpiry(claimsSet);

        var decoded = new DecodedStatusList(statusBits, bitsPerStatus);
        CACHE.put(uri, new CachedStatusList(decoded, expiresAt));
        return decoded;
    }

    private void verifyStatusListJwtSignature(SignedJWT signedJWT) throws Exception {
        List<PublicKey> keys = trustListProvider != null ? trustListProvider.getTrustedKeys() : List.of();
        if (keys.isEmpty()) {
            LOG.debugf(
                    "Status list JWT signature not verified: no trusted keys configured (issuer=%s)",
                    signedJWT.getJWTClaimsSet().getIssuer());
            return;
        }

        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
        for (PublicKey key : keys) {
            try {
                JWSVerifier verifier = factory.createJWSVerifier(signedJWT.getHeader(), key);
                if (signedJWT.verify(verifier)) {
                    LOG.debugf(
                            "Status list JWT signature verified (issuer: %s)",
                            signedJWT.getJWTClaimsSet().getIssuer());
                    return;
                }
            } catch (Exception e) {
                // Key type doesn't match algorithm — try next key
            }
        }

        throw new IllegalStateException("Status list JWT signature verification failed: no trusted key matched");
    }

    private Instant resolveExpiry(JWTClaimsSet claimsSet) {
        Date exp = claimsSet.getExpirationTime();
        Instant expiry = exp != null ? exp.toInstant() : Instant.now();
        if (maxCacheTtl != null) {
            Instant maxExpiry = Instant.now().plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    private String fetchStatusListJwt(String uri) throws Exception {
        if (session != null) {
            return SimpleHttp.doGet(uri, session)
                    .header("Accept", "application/statuslist+jwt")
                    .asString();
        }
        // Fallback for tests without KeycloakSession
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    static byte[] inflate(byte[] compressed) throws Exception {
        try {
            return new InflaterInputStream(new ByteArrayInputStream(compressed)).readAllBytes();
        } catch (Exception e) {
            // Fallback: try raw DEFLATE (without zlib header)
            return new InflaterInputStream(new ByteArrayInputStream(compressed), new Inflater(true)).readAllBytes();
        }
    }

    static int getStatusAtIndex(byte[] statusBits, int idx, int bitsPerStatus) {
        if (statusBits == null || statusBits.length == 0) {
            throw new IllegalStateException("Empty status list");
        }
        if (bitsPerStatus < 1 || bitsPerStatus > 8) {
            throw new IllegalArgumentException("bitsPerStatus must be 1-8, got " + bitsPerStatus);
        }
        int bitOffset = idx * bitsPerStatus;
        int byteIndex = bitOffset / 8;
        int bitIndex = bitOffset % 8;

        if (byteIndex >= statusBits.length) {
            throw new IllegalStateException("Status index " + idx + " out of range (list has "
                    + (statusBits.length * 8 / bitsPerStatus) + " entries)");
        }

        int mask = ((1 << bitsPerStatus) - 1);
        return (statusBits[byteIndex] >> bitIndex) & mask;
    }

    /** Clears the static cache. Intended for testing only. */
    static void clearCache() {
        CACHE.clear();
    }

    record StatusReference(String uri, int idx) {}

    record DecodedStatusList(byte[] statusBits, int bitsPerStatus) {}

    private record CachedStatusList(DecodedStatusList decoded, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
