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
import de.arbeitsagentur.keycloak.oid4vp.event.RevocationCheckFailedEvent;
import de.arbeitsagentur.keycloak.oid4vp.event.RevocationDetectedEvent;
import de.arbeitsagentur.keycloak.oid4vp.event.RevocationMechanism;
import de.arbeitsagentur.keycloak.oid4vp.trust.CrlPolicy;
import de.arbeitsagentur.keycloak.oid4vp.trust.IssuerTrustAnchors;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.util.BoundedLruMap;
import de.arbeitsagentur.keycloak.oid4vp.util.CertificateFingerprints;
import de.arbeitsagentur.keycloak.oid4vp.util.FailureDetails;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.executors.ExecutorsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Checks the certificates of a validated issuer chain against the CRLs of their CAs (ARF section
 * 6.6.6.4, ISO/IEC 18013-5:2021 section 9.3.3). Trust anchors and pinned certificates are skipped,
 * because the trust source withdraws those itself.
 *
 * <p>The URLs and time limits come from the {@link CrlPolicy} of the trust domain that accepts the
 * chain, and that domain keeps its own cached CRLs. A background task fetches a CRL that is missing
 * or expired. A login uses the cached CRL, and only waits a bounded time when none is known yet.
 *
 * <p>A failed fetch logs a warning and is cached, and the last known CRL stays in use if there is
 * one, so a revoked certificate on it stays rejected. Without a known CRL the {@code required} flag
 * of the policy decides whether the credential is rejected, and that login then tries a download
 * itself instead of relying on the cached failure.
 */
public class CrlVerifier {

    public static final CrlVerifier DISABLED = new CrlVerifier(null) {
        @Override
        public void check(List<X509Certificate> chain, ResolvedTrust trust) {}
    };

    private static final Logger LOG = Logger.getLogger(CrlVerifier.class);
    private static final String EXECUTOR = "oid4vp-crl-refresh";
    private static final int MAX_CACHE_ENTRIES = 256;
    private static final int MAX_CRL_BYTES = 16 * 1024 * 1024;
    private static final Duration MAX_DOWNLOAD_TIME = Duration.ofSeconds(30);
    private static final Duration FIRST_FETCH_WAIT = Duration.ofSeconds(3);
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);
    private static final String CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    private static final String DELTA_CRL_INDICATOR = "2.5.29.27";
    private static final String ISSUING_DISTRIBUTION_POINT = "2.5.29.28";

    private static final Map<String, Map<CacheKey, CachedCrl>> CACHES = new ConcurrentHashMap<>();
    private static final Map<CacheKey, CompletableFuture<Void>> REFRESHING = new ConcurrentHashMap<>();

    private final KeycloakSession session;

    public CrlVerifier(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Rejects a chain with a revoked certificate. Expects a validated chain, because the
     * CRL URLs come from its certificates.
     */
    public void check(List<X509Certificate> chain, ResolvedTrust trust) throws VerificationException {
        IssuerTrustAnchors domain = trust.domainAccepting(chain);
        if (domain == null) {
            return;
        }
        Set<X509Certificate> anchors = domain.trustAnchors();
        List<X509Certificate> candidates =
                Stream.concat(chain.stream(), anchors.stream()).toList();
        List<X509Certificate> pinned = trust.pinnedCertificates();
        CrlPolicy policy = domain.crlPolicy();

        List<X509Certificate> path = pathToAnchor(chain.get(0), candidates, anchors, new HashSet<>());
        if (path.isEmpty()) {
            warnUnchecked(policy, "No path to a trust anchor from ", chain.get(0));
            return;
        }
        for (int depth = 0; depth < path.size() - 1; depth++) {
            X509Certificate certificate = path.get(depth);
            if (!pinned.contains(certificate)) {
                checkCertificate(certificate, path.get(depth + 1), depth == 0, policy);
            }
        }
    }

    /**
     * Follows only certificates that lead to a trust anchor. A chain can list other certificates,
     * which path validation ignores, and in an mDoc the holder can add them. A forged copy of an
     * intermediate carries its public key, so without this check it would pass as the issuer of the
     * leaf and end the walk before the real intermediate.
     */
    private static List<X509Certificate> pathToAnchor(
            X509Certificate certificate,
            List<X509Certificate> candidates,
            Set<X509Certificate> anchors,
            Set<X509Certificate> visited) {
        if (anchors.contains(certificate)) {
            return List.of(certificate);
        }
        if (!visited.add(certificate)) {
            return List.of();
        }
        for (X509Certificate candidate : candidates) {
            if (isIssuerOf(candidate, certificate, anchors)) {
                List<X509Certificate> rest = pathToAnchor(candidate, candidates, anchors, visited);
                if (!rest.isEmpty()) {
                    return Stream.concat(Stream.of(certificate), rest.stream()).toList();
                }
            }
        }
        return List.of();
    }

    private void checkCertificate(X509Certificate certificate, X509Certificate issuer, boolean leaf, CrlPolicy policy)
            throws VerificationException {
        List<String> urls = crlUrls(certificate, leaf, policy);
        if (urls.isEmpty()) {
            return;
        }
        X509CRL crl = loadCrl(urls, issuer, policy);
        if (crl == null) {
            if (policy.required()) {
                throw new RevocationStatusUnavailableException(
                        "No CRL is available for " + FailureDetails.certificate(certificate));
            }
            return;
        }
        if (crl.isRevoked(certificate)) {
            Oid4vpEventService.fire(
                    session,
                    new RevocationDetectedEvent(
                            Oid4vpEventService.realmId(session),
                            policy.providerId(),
                            RevocationMechanism.CRL,
                            FailureDetails.certificate(certificate),
                            Oid4vpEventService.state(session)));
            throw new VerificationException(
                    "Issuer certificate has been revoked: " + FailureDetails.certificate(certificate));
        }
    }

    private static boolean isIssuerOf(
            X509Certificate candidate, X509Certificate certificate, Set<X509Certificate> anchors) {
        if (candidate.equals(certificate)
                || !candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            // Skips an expired certificate, because PKIX skips it too. An old copy of a renewed
            // intermediate would otherwise hide a revocation of the current one.
            if (!anchors.contains(candidate)) {
                candidate.checkValidity();
            }
            certificate.verify(candidate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private List<String> crlUrls(X509Certificate certificate, boolean leaf, CrlPolicy policy) {
        if (leaf && policy.endpoint() != null) {
            return List.of(policy.endpoint());
        }
        List<String> distributionPoints;
        try {
            distributionPoints =
                    CryptoIntegration.getProvider().getCertificateUtils().getCRLDistributionPoints(certificate);
        } catch (IOException | RuntimeException e) {
            warnUnchecked(policy, "Unable to read the CRL distribution points of ", certificate);
            return List.of();
        }
        List<String> urls = distributionPoints.stream()
                .filter(url -> url.regionMatches(true, 0, "http", 0, 4))
                .toList();
        // Asks the certificate, because Keycloak returns only URI distribution points.
        if (urls.isEmpty() && certificate.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null) {
            warnUnchecked(policy, "No http(s) CRL distribution point in ", certificate);
        }
        return urls;
    }

    private void warnUnchecked(CrlPolicy policy, String reason, X509Certificate certificate) {
        String message = reason + FailureDetails.certificate(certificate);
        LOG.warnf("Checking the certificate against no CRL: %s", message);
        fireCheckFailed(session, Oid4vpEventService.realmId(session), policy, List.of(), false, message);
        if (policy.required()) {
            throw new RevocationStatusUnavailableException(message);
        }
    }

    private X509CRL loadCrl(List<String> urls, X509Certificate issuer, CrlPolicy policy) {
        CacheKey key = new CacheKey(policy.providerId(), urls, CertificateFingerprints.of(List.of(issuer)));
        CachedCrl cached = cacheOf(policy).get(key);
        // Skips a cached failure under a required CRL, because only a current attempt may reject a login.
        if (cached != null && Instant.now().isBefore(cached.expiresAt) && (cached.crl != null || !policy.required())) {
            return cached.crl;
        }
        String realmId = Oid4vpEventService.realmId(session);
        CompletableFuture<Void> refresh = refreshInBackground(key, issuer, policy, realmId);
        if (cached != null && cached.crl != null) {
            return cached.crl;
        }
        // Waits, because otherwise the first presentation for a rarely used issuer always goes unchecked.
        refresh.copy()
                .completeOnTimeout(null, firstFetchWait().toMillis(), TimeUnit.MILLISECONDS)
                .join();
        CachedCrl loaded = cacheOf(policy).get(key);
        if (loaded != null && loaded.crl != null) {
            return loaded.crl;
        }
        LOG.warnf("Checking the credential against no CRL: %s", urls);
        fireCheckFailed(session, realmId, policy, urls, false, "No CRL is available");
        return null;
    }

    Duration firstFetchWait() {
        return FIRST_FETCH_WAIT;
    }

    // Keeps one map per provider, so a provider with many CRLs cannot evict the CRLs of another.
    private static Map<CacheKey, CachedCrl> cacheOf(CrlPolicy policy) {
        return CACHES.computeIfAbsent(
                String.valueOf(policy.providerId()), id -> BoundedLruMap.withMaxEntries(MAX_CACHE_ENTRIES));
    }

    /**
     * Caches the failure like a CRL, so without a required CRL an unreachable endpoint costs one attempt
     * per cache TTL. Works on the current entry, because a concurrent fetch may have stored a CRL
     * meanwhile.
     */
    private static void cacheFailure(
            KeycloakSession session, String realmId, CacheKey key, CrlPolicy policy, VerificationException e) {
        CachedCrl entry = cacheOf(policy).compute(key, (cacheKey, current) -> {
            Instant now = Instant.now();
            if (current != null && now.isBefore(current.expiresAt)) {
                return current;
            }
            X509CRL lastKnown = current != null ? current.crl : null;
            return new CachedCrl(lastKnown, now.plus(policy.maxCacheTtl()));
        });
        LOG.warnf(
                "Checking credentials against %s until %s: %s",
                entry.crl != null ? "the last known CRL" : "no CRL", entry.expiresAt, e.getMessage());
        fireCheckFailed(session, realmId, policy, key.urls, entry.crl != null, e.getMessage());
    }

    private static void fireCheckFailed(
            KeycloakSession session,
            String realmId,
            CrlPolicy policy,
            List<String> urls,
            boolean staleDataInUse,
            String reason) {
        Oid4vpEventService.fire(
                session,
                new RevocationCheckFailedEvent(
                        realmId,
                        policy.providerId(),
                        RevocationMechanism.CRL,
                        urls.isEmpty() ? null : String.join(",", urls),
                        Oid4vpEventService.state(session),
                        staleDataInUse,
                        reason));
    }

    private CompletableFuture<Void> refreshInBackground(
            CacheKey key, X509Certificate issuer, CrlPolicy policy, String realmId) {
        CompletableFuture<Void> refresh = new CompletableFuture<>();
        CompletableFuture<Void> running = REFRESHING.putIfAbsent(key, refresh);
        if (running != null) {
            return running;
        }
        Runnable done = () -> {
            REFRESHING.remove(key);
            refresh.complete(null);
        };
        try {
            runInBackground(
                    backgroundSession -> {
                        try {
                            fetchAndCache(backgroundSession, key, issuer, policy);
                        } catch (VerificationException e) {
                            cacheFailure(backgroundSession, realmId, key, policy, e);
                        }
                    },
                    done);
        } catch (RuntimeException e) {
            done.run();
            LOG.warnf("The CRL refresh could not start: %s", FailureDetails.causeChain(e));
        }
        return refresh;
    }

    // Opens a session of its own, because the session of the login ends before the refresh does.
    // Runs `done` even when that session cannot start, otherwise the CRL never refreshes again.
    void runInBackground(KeycloakSessionTask task, Runnable done) {
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        session.getProvider(ExecutorsProvider.class).getExecutor(EXECUTOR).execute(() -> {
            try {
                KeycloakModelUtils.runJobInTransaction(sessionFactory, task);
            } finally {
                done.run();
            }
        });
    }

    private void fetchAndCache(KeycloakSession session, CacheKey key, X509Certificate issuer, CrlPolicy policy)
            throws VerificationException {
        List<String> failures = new ArrayList<>();
        for (String url : key.urls) {
            try {
                X509CRL crl = fetchValidCrl(session, url, issuer);
                requireNotOlderThanCached(crl, key, policy);
                cacheOf(policy).put(key, new CachedCrl(crl, resolveExpiry(crl, policy.maxCacheTtl())));
                return;
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                failures.add(url + ": " + FailureDetails.causeChain(e));
            }
        }
        throw new VerificationException("Unable to fetch CRL: " + FailureDetails.singleLine(failures.toString()));
    }

    // Rejects an older CRL, because CRLs travel over plain http and an attacker on the path can replay
    // one that omits a revoked certificate.
    private static void requireNotOlderThanCached(X509CRL crl, CacheKey key, CrlPolicy policy) throws CRLException {
        CachedCrl cached = cacheOf(policy).get(key);
        if (cached != null && cached.crl != null && crl.getThisUpdate().before(cached.crl.getThisUpdate())) {
            throw new CRLException("CRL of " + crl.getThisUpdate() + " is older than the cached one");
        }
    }

    private X509CRL fetchValidCrl(KeycloakSession session, String url, X509Certificate issuer)
            throws IOException, GeneralSecurityException {
        byte[] body = fetchCrl(session, url);
        if (!(CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(body))
                instanceof X509CRL crl)) {
            throw new CRLException("Response is not an X.509 CRL");
        }
        if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            throw new CRLException(
                    "CRL issuer " + crl.getIssuerX500Principal() + " is not " + issuer.getSubjectX500Principal());
        }
        crl.verify(issuer.getPublicKey());
        // Rejects delta and scoped CRLs, because they list only part of the revocations (RFC 5280
        // sections 5.2.4 and 5.2.5).
        if (crl.getExtensionValue(DELTA_CRL_INDICATOR) != null
                || crl.getExtensionValue(ISSUING_DISTRIBUTION_POINT) != null) {
            throw new CRLException("Delta and scoped CRLs are not supported");
        }
        if (crl.hasUnsupportedCriticalExtension()) {
            throw new CRLException("CRL has an unsupported critical extension");
        }
        // Rejects a future date, because such a CRL would count as newer than every later one.
        if (crl.getThisUpdate().toInstant().isAfter(Instant.now().plus(MAX_CLOCK_SKEW))) {
            throw new CRLException(
                    "CRL is dated in the future: " + crl.getThisUpdate().toInstant());
        }
        if (crl.getNextUpdate() != null && crl.getNextUpdate().toInstant().isBefore(Instant.now())) {
            throw new CRLException("CRL expired at " + crl.getNextUpdate().toInstant());
        }
        return crl;
    }

    private static Instant resolveExpiry(X509CRL crl, Duration maxCacheTtl) {
        Instant maxExpiry = Instant.now().plus(maxCacheTtl);
        if (crl.getNextUpdate() == null) {
            return maxExpiry;
        }
        Instant nextUpdate = crl.getNextUpdate().toInstant();
        return nextUpdate.isBefore(maxExpiry) ? nextUpdate : maxExpiry;
    }

    byte[] fetchCrl(KeycloakSession session, String url) throws IOException {
        try (InputStream body = session.getProvider(HttpClientProvider.class).getInputStream(url)) {
            return readCrl(body, Instant.now().plus(MAX_DOWNLOAD_TIME));
        }
    }

    // Enforces a deadline for the whole download, because the socket timeout limits a single read.
    static byte[] readCrl(InputStream body, Instant deadline) throws IOException {
        ByteArrayOutputStream crl = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        for (int read = body.read(buffer); read != -1; read = body.read(buffer)) {
            crl.write(buffer, 0, read);
            if (crl.size() > MAX_CRL_BYTES) {
                throw new IOException("CRL exceeds " + MAX_CRL_BYTES + " bytes");
            }
            if (Instant.now().isAfter(deadline)) {
                throw new IOException("CRL download exceeds " + MAX_DOWNLOAD_TIME);
            }
        }
        return crl.toByteArray();
    }

    private record CacheKey(String providerId, List<String> urls, List<String> issuerFingerprints) {}

    private record CachedCrl(X509CRL crl, Instant expiresAt) {}
}
