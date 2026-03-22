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
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Resolves issuer signing keys for SD-JWT VCs using JWT VC Issuer Metadata.
 *
 * <p>Given an HTTPS issuer identifier and a JOSE {@code kid}, this resolver fetches the issuer's
 * metadata from {@code /.well-known/jwt-vc-issuer}, optionally follows {@code jwks_uri}, caches
 * the discovered key material for a bounded time, and returns the matching public key.
 */
public class JwtVcIssuerMetadataResolver {

    private static final Logger LOG = Logger.getLogger(JwtVcIssuerMetadataResolver.class);
    private static final String WELL_KNOWN_PATH = "/.well-known/jwt-vc-issuer";
    private static final HttpClient HTTP_CLIENT =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    private static final ConcurrentHashMap<CacheKey, CachedIssuerKeys> CACHE = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final Duration maxCacheTtl;

    public JwtVcIssuerMetadataResolver(Duration maxCacheTtl) {
        this(null, maxCacheTtl);
    }

    public JwtVcIssuerMetadataResolver(KeycloakSession session, Duration maxCacheTtl) {
        this.session = session;
        this.maxCacheTtl = maxCacheTtl != null ? maxCacheTtl : Duration.ofDays(1);
    }

    public ResolvedIssuerKey resolveSigningKey(String issuer, String kid) {
        String normalizedIssuer = normalizeIssuer(issuer);
        if (kid == null || kid.isBlank()) {
            throw new IllegalStateException("SD-JWT issuer JWT header is missing required kid");
        }

        CacheKey cacheKey = new CacheKey(normalizedIssuer, maxCacheTtl);
        CachedIssuerKeys cached = CACHE.get(cacheKey);
        if (cached != null && cached.isValid()) {
            ResolvedIssuerKey key = cached.find(kid);
            if (key != null) {
                return key;
            }
            LOG.debugf("Issuer metadata cache miss for kid=%s issuer=%s, forcing refresh", kid, normalizedIssuer);
        }

        CachedIssuerKeys refreshed = fetchIssuerKeys(normalizedIssuer);
        if (refreshed.expiresAt() != null) {
            CACHE.put(cacheKey, refreshed);
        } else {
            CACHE.remove(cacheKey);
        }

        ResolvedIssuerKey key = refreshed.find(kid);
        if (key == null) {
            throw new IllegalStateException(
                    "Issuer metadata for " + normalizedIssuer + " does not contain a signing key for kid " + kid);
        }
        return key;
    }

    protected FetchResult fetchJson(String url) throws Exception {
        if (session != null) {
            try (SimpleHttp.Response response =
                    SimpleHttp.doGet(url, session).acceptJson().asResponse()) {
                if (response.getStatus() != 200) {
                    throw new IllegalStateException("Unexpected HTTP " + response.getStatus() + " fetching " + url);
                }
                return new FetchResult(
                        response.asJson(), parseCacheControlMaxAge(response.getHeader("Cache-Control")), Instant.now());
            }
        }

        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected HTTP " + response.statusCode() + " fetching " + url);
        }
        return new FetchResult(
                JsonSerialization.mapper.readTree(response.body()), parseCacheControlMaxAge(response), Instant.now());
    }

    private CachedIssuerKeys fetchIssuerKeys(String issuer) {
        try {
            FetchResult metadataResult = fetchJson(buildMetadataUrl(issuer));
            JsonNode metadata = metadataResult.json();

            String metadataIssuer = metadata.path("issuer").textValue();
            if (metadataIssuer == null || !issuer.equals(metadataIssuer)) {
                throw new IllegalStateException("Issuer metadata issuer does not match SD-JWT issuer");
            }

            FetchResult jwksResult = metadataResult;
            JSONWebKeySet jwks;
            JsonNode jwksNode = metadata.get("jwks");
            String jwksUri = metadata.path("jwks_uri").textValue();
            if (jwksNode != null && !jwksNode.isMissingNode() && !jwksNode.isNull()) {
                jwks = parseJsonWebKeySet(jwksNode);
            } else if (jwksUri != null) {
                jwksResult = fetchJson(jwksUri);
                jwks = fetchRemoteJwks(jwksUri, jwksResult.json());
            } else {
                throw new IllegalStateException("Issuer metadata does not contain jwks or jwks_uri");
            }

            Instant baseExpiry = computeBaseExpiry(metadataResult, jwksResult);
            List<ResolvedIssuerKey> keys = parseJwks(jwks, baseExpiry);
            Instant expiresAt = computeCacheExpiry(keys, baseExpiry);
            return new CachedIssuerKeys(keys, expiresAt);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to resolve issuer metadata for " + issuer + ": " + e.getMessage(), e);
        }
    }

    protected JSONWebKeySet fetchRemoteJwks(String url, JsonNode fallbackJwksDocument) throws Exception {
        if (session != null) {
            return JWKSHttpUtils.sendJwksRequest(session, url);
        }
        return parseJsonWebKeySet(fallbackJwksDocument);
    }

    protected JSONWebKeySet parseJsonWebKeySet(JsonNode rawJwks) {
        try {
            JSONWebKeySet jwks = JsonSerialization.mapper.treeToValue(rawJwks, JSONWebKeySet.class);
            if (jwks == null) {
                throw new IllegalStateException("JWKS document is empty");
            }
            return jwks;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse issuer JWKS", e);
        }
    }

    private List<ResolvedIssuerKey> parseJwks(JSONWebKeySet jwks, Instant baseExpiry) {
        JWK[] rawKeys = jwks.getKeys();
        if (rawKeys == null || rawKeys.length == 0) {
            throw new IllegalStateException("JWKS does not contain any keys");
        }

        List<ResolvedIssuerKey> keys = new ArrayList<>();
        for (JWK jwk : rawKeys) {
            ResolvedIssuerKey resolvedKey = toResolvedIssuerKey(jwk, baseExpiry);
            if (resolvedKey != null) {
                keys.add(resolvedKey);
            }
        }

        if (keys.isEmpty()) {
            throw new IllegalStateException("JWKS does not contain any usable signing keys");
        }
        return List.copyOf(keys);
    }

    private ResolvedIssuerKey toResolvedIssuerKey(JWK jwk, Instant baseExpiry) {
        if (jwk == null) {
            return null;
        }
        if (jwk.getPublicKeyUse() != null && !"sig".equalsIgnoreCase(jwk.getPublicKeyUse())) {
            return null;
        }
        String kid = jwk.getKeyId();
        if (kid == null || kid.isBlank()) {
            return null;
        }
        return new ResolvedIssuerKey(
                kid, toPublicKey(jwk), extractCertificateChain(jwk), resolveKeyExpiry(jwk, baseExpiry));
    }

    private PublicKey toPublicKey(JWK jwk) {
        try {
            KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
            if (keyWrapper != null && keyWrapper.getPublicKey() instanceof PublicKey publicKey) {
                return publicKey;
            }
            throw new IllegalStateException("Unsupported issuer JWK type: " + jwk.getKeyType());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert issuer JWK to public key", e);
        }
    }

    private List<X509Certificate> extractCertificateChain(JWK jwk) {
        String[] chain = jwk.getX509CertificateChain();
        if (chain == null || chain.length == 0) {
            return List.of();
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>(chain.length);
            for (String certB64 : chain) {
                certificates.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(Base64.getMimeDecoder().decode(certB64))));
            }
            return List.copyOf(certificates);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse x5c from issuer JWK", e);
        }
    }

    private String normalizeIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("SD-JWT VC is missing iss");
        }
        URI uri = URI.create(issuer);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalStateException("SD-JWT issuer must be an HTTPS URL for web-based key resolution");
        }
        if (uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalStateException("SD-JWT issuer URL must not contain query or fragment components");
        }
        return uri.toString();
    }

    private String buildMetadataUrl(String issuer) {
        try {
            URI issuerUri = URI.create(issuer);
            String path = issuerUri.getPath();
            if (path == null || path.isBlank() || "/".equals(path)) {
                path = "";
            } else if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return new URI(
                            issuerUri.getScheme(),
                            issuerUri.getUserInfo(),
                            issuerUri.getHost(),
                            issuerUri.getPort(),
                            WELL_KNOWN_PATH + path,
                            null,
                            null)
                    .toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JWT VC issuer metadata URL", e);
        }
    }

    private Instant computeBaseExpiry(FetchResult metadataResult, FetchResult jwksResult) {
        Duration metadataTtl = effectiveTtl(metadataResult.cacheTtl());
        Duration jwksTtl = effectiveTtl(jwksResult.cacheTtl());
        Duration ttl = metadataTtl.compareTo(jwksTtl) <= 0 ? metadataTtl : jwksTtl;
        if (ttl.isZero() || ttl.isNegative()) {
            return null;
        }
        Instant base = metadataResult.fetchedAt().isAfter(jwksResult.fetchedAt())
                ? metadataResult.fetchedAt()
                : jwksResult.fetchedAt();
        return base.plus(ttl);
    }

    private Instant resolveKeyExpiry(JWK jwk, Instant baseExpiry) {
        Map<String, Object> otherClaims = jwk.getOtherClaims();
        Object expValue = otherClaims != null ? otherClaims.get("exp") : null;
        Instant jwkExpiry = null;
        if (expValue instanceof Number number) {
            jwkExpiry = Instant.ofEpochSecond(number.longValue());
        } else if (expValue instanceof String text) {
            try {
                jwkExpiry = Instant.ofEpochSecond(Long.parseLong(text));
            } catch (NumberFormatException ignored) {
            }
        }
        if (baseExpiry == null) {
            return jwkExpiry;
        }
        if (jwkExpiry == null) {
            return baseExpiry;
        }
        return jwkExpiry.isBefore(baseExpiry) ? jwkExpiry : baseExpiry;
    }

    private Instant computeCacheExpiry(List<ResolvedIssuerKey> keys, Instant baseExpiry) {
        Instant latestKeyExpiry = null;
        for (ResolvedIssuerKey key : keys) {
            if (key.expiresAt() != null
                    && (latestKeyExpiry == null || key.expiresAt().isAfter(latestKeyExpiry))) {
                latestKeyExpiry = key.expiresAt();
            }
        }
        if (baseExpiry == null) {
            return latestKeyExpiry;
        }
        if (latestKeyExpiry == null) {
            return baseExpiry;
        }
        return latestKeyExpiry.isBefore(baseExpiry) ? latestKeyExpiry : baseExpiry;
    }

    private Duration effectiveTtl(Duration responseTtl) {
        if (responseTtl == null) {
            return maxCacheTtl;
        }
        return responseTtl.compareTo(maxCacheTtl) <= 0 ? responseTtl : maxCacheTtl;
    }

    private Duration parseCacheControlMaxAge(HttpResponse<?> response) {
        return parseCacheControlMaxAge(response.headers().allValues("Cache-Control"));
    }

    private Duration parseCacheControlMaxAge(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return parseCacheControlMaxAge(List.of(value));
    }

    private Duration parseCacheControlMaxAge(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        for (String header : values) {
            for (String directive : header.split(",")) {
                String trimmed = directive.trim();
                if (trimmed.startsWith("max-age=")) {
                    try {
                        return Duration.ofSeconds(Long.parseLong(trimmed.substring("max-age=".length())));
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
        return null;
    }

    protected record FetchResult(JsonNode json, Duration cacheTtl, Instant fetchedAt) {
        protected FetchResult {
            Objects.requireNonNull(json);
            Objects.requireNonNull(fetchedAt);
        }
    }

    private record CacheKey(String issuer, Duration maxCacheTtl) {}

    private record CachedIssuerKeys(List<ResolvedIssuerKey> keys, Instant expiresAt) {
        boolean isValid() {
            return expiresAt != null && Instant.now().isBefore(expiresAt);
        }

        ResolvedIssuerKey find(String kid) {
            Instant now = Instant.now();
            return keys.stream()
                    .filter(key -> key.kid().equals(kid))
                    .filter(key -> key.expiresAt() == null || now.isBefore(key.expiresAt()))
                    .findFirst()
                    .orElse(null);
        }
    }

    public record ResolvedIssuerKey(
            String kid, PublicKey publicKey, List<X509Certificate> certificateChain, Instant expiresAt) {
        public ResolvedIssuerKey {
            Objects.requireNonNull(kid);
            Objects.requireNonNull(publicKey);
            certificateChain = certificateChain != null ? List.copyOf(certificateChain) : List.of();
        }
    }
}
