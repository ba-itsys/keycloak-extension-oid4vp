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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Fetches and caches an ETSI TS 119 602 trust list JWT from a configured URL.
 * Extracts X.509 issuer certificates and their public keys for credential verification.
 *
 * <p>When a signing certificate is configured, the trust list JWT signature is verified
 * before extracting certificates. Without a signing certificate, the JWT is accepted
 * without signature verification.
 */
public class TrustListProvider {

    private static final Logger LOG = Logger.getLogger(TrustListProvider.class);
    private static final ConcurrentHashMap<String, CachedTrustList> CACHE = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final String trustListUrl;
    private final List<X509Certificate> staticCertificates;
    private final Duration maxCacheTtl;
    private final List<X509Certificate> signingCertificates;

    /** Creates a provider that fetches the trust list from the given URL. */
    public TrustListProvider(KeycloakSession session, String trustListUrl) {
        this(session, trustListUrl, null, (List<X509Certificate>) null);
    }

    /** Creates a provider that fetches the trust list from the given URL with a cache TTL cap. */
    public TrustListProvider(KeycloakSession session, String trustListUrl, Duration maxCacheTtl) {
        this(session, trustListUrl, maxCacheTtl, (List<X509Certificate>) null);
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
        this.session = session;
        this.trustListUrl = trustListUrl;
        this.staticCertificates = null;
        this.maxCacheTtl = maxCacheTtl;
        this.signingCertificates = signingCertificates;
    }

    /** Creates a provider with static trusted certificates. Useful for testing. */
    public TrustListProvider(List<X509Certificate> staticCertificates) {
        this.session = null;
        this.trustListUrl = null;
        this.staticCertificates = staticCertificates;
        this.maxCacheTtl = null;
        this.signingCertificates = null;
    }

    /**
     * Returns trusted public keys from the configured trust list.
     * Results are cached based on the JWT exp claim.
     */
    public List<PublicKey> getTrustedKeys() {
        return getTrustedCertificates().stream()
                .map(X509Certificate::getPublicKey)
                .toList();
    }

    /**
     * Returns trusted X.509 certificates from the configured trust list.
     * Results are cached based on the JWT exp claim.
     */
    public List<X509Certificate> getTrustedCertificates() {
        if (staticCertificates != null) {
            return staticCertificates;
        }

        if (trustListUrl == null || trustListUrl.isBlank()) {
            return List.of();
        }

        CachedTrustList cached = CACHE.get(trustListUrl);
        if (cached != null && cached.isValid()) {
            LOG.debugf("Using cached trust list for %s (expires %s)", trustListUrl, cached.expiresAt);
            return cached.certificates;
        }

        try {
            String jwt = fetchTrustListJwt();
            verifySignature(jwt);
            TrustListParseResult result = parseTrustListJwt(jwt);

            Instant effectiveExpiry = capExpiry(result.expiresAt);
            CACHE.put(trustListUrl, new CachedTrustList(result.certificates, effectiveExpiry));

            LOG.infof(
                    "Trust list loaded from %s: %d keys (expires %s)",
                    trustListUrl, result.certificates.size(), result.expiresAt);
            return result.certificates;
        } catch (Exception e) {
            LOG.warnf("Failed to fetch trust list from %s: %s", trustListUrl, e.getMessage());
            return List.of();
        }
    }

    void verifySignature(String jwt) throws Exception {
        if (signingCertificates == null || signingCertificates.isEmpty()) {
            LOG.debugf("Trust list JWT signature not verified: no signing certificate configured");
            return;
        }

        SignedJWT signedJWT = SignedJWT.parse(jwt);

        // Try x5c chain validation first
        List<String> x5c = signedJWT.getHeader().getX509CertChain() != null
                ? signedJWT.getHeader().getX509CertChain().stream()
                        .map(c -> c.toString())
                        .toList()
                : null;
        if (x5c != null && !x5c.isEmpty()) {
            try {
                PublicKey leafKey = X5cChainValidator.validateChain(x5c, signingCertificates);
                DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
                JWSVerifier verifier = factory.createJWSVerifier(signedJWT.getHeader(), leafKey);
                if (signedJWT.verify(verifier)) {
                    LOG.debugf("Trust list JWT signature verified via x5c chain");
                    return;
                }
            } catch (Exception e) {
                LOG.debugf("Trust list JWT x5c chain validation failed: %s", e.getMessage());
            }
        }

        // Fallback: try each configured certificate's public key directly
        DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
        for (X509Certificate cert : signingCertificates) {
            try {
                JWSVerifier verifier = factory.createJWSVerifier(signedJWT.getHeader(), cert.getPublicKey());
                if (signedJWT.verify(verifier)) {
                    LOG.debugf("Trust list JWT signature verified against configured signing certificate");
                    return;
                }
            } catch (Exception e) {
                // Key type doesn't match algorithm — try next
            }
        }

        throw new IllegalStateException(
                "Trust list JWT signature verification failed: signature does not match any configured signing certificate");
    }

    private Instant capExpiry(Instant expiry) {
        if (maxCacheTtl != null) {
            Instant maxExpiry = Instant.now().plus(maxCacheTtl);
            return expiry.isBefore(maxExpiry) ? expiry : maxExpiry;
        }
        return expiry;
    }

    private String fetchTrustListJwt() throws Exception {
        if (session != null) {
            return SimpleHttp.doGet(trustListUrl, session)
                    .header("Accept", "application/jwt")
                    .asString();
        }
        throw new IllegalStateException("No KeycloakSession available for HTTP requests");
    }

    @SuppressWarnings("unchecked")
    static TrustListParseResult parseTrustListJwt(String jwt) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Date exp = claimsSet.getExpirationTime();
        Instant expiresAt = exp != null ? exp.toInstant() : Instant.now();

        List<X509Certificate> certificates = new ArrayList<>();

        List<Map<String, Object>> entitiesList = (List<Map<String, Object>>) claimsSet.getClaim("TrustedEntitiesList");
        if (entitiesList != null) {
            for (Map<String, Object> entity : entitiesList) {
                List<Map<String, Object>> services = (List<Map<String, Object>>) entity.get("TrustedEntityServices");
                if (services == null) continue;

                for (Map<String, Object> service : services) {
                    Map<String, Object> serviceInfo = (Map<String, Object>) service.get("ServiceInformation");
                    if (serviceInfo == null) continue;

                    Map<String, Object> digitalIdentity =
                            (Map<String, Object>) serviceInfo.get("ServiceDigitalIdentity");
                    if (digitalIdentity == null) continue;

                    List<Map<String, Object>> x509Certs =
                            (List<Map<String, Object>>) digitalIdentity.get("X509Certificates");
                    if (x509Certs == null) continue;

                    for (Map<String, Object> certEntry : x509Certs) {
                        Object val = certEntry.get("val");
                        if (val == null) continue;

                        try {
                            byte[] certDer = Base64.getDecoder().decode(val.toString());
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            X509Certificate cert =
                                    (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
                            certificates.add(cert);
                            LOG.debugf(
                                    "Loaded trusted certificate: %s",
                                    cert.getSubjectX500Principal().getName());
                        } catch (Exception e) {
                            LOG.warnf("Failed to parse certificate from trust list: %s", e.getMessage());
                        }
                    }
                }
            }
        }

        return new TrustListParseResult(certificates, expiresAt);
    }

    /** Clears the static cache. Intended for testing only. */
    static void clearCache() {
        CACHE.clear();
    }

    record TrustListParseResult(List<X509Certificate> certificates, Instant expiresAt) {}

    private record CachedTrustList(List<X509Certificate> certificates, Instant expiresAt) {
        boolean isValid() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
