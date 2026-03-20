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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class JwtVcIssuerMetadataResolverTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String ISSUER = "https://issuer.example/tenant/123";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(JwtVcIssuerMetadataResolverTest.class.getClassLoader());
    }

    @Test
    void resolveSigningKey_usesCachedEntryUntilKeyExpiry() throws Exception {
        ECKey activeKey = new ECKeyGenerator(Curve.P_256).keyID("active").generate();
        FakeResolver resolver = new FakeResolver(Duration.ofDays(1));
        resolver.stubMetadata(
                ISSUER,
                buildMetadata(
                        ISSUER,
                        buildJwks(activeKey, Instant.now().plusSeconds(3600).getEpochSecond())),
                Duration.ofMinutes(30));

        JwtVcIssuerMetadataResolver.ResolvedIssuerKey first = resolver.resolveSigningKey(ISSUER, "active");
        JwtVcIssuerMetadataResolver.ResolvedIssuerKey second = resolver.resolveSigningKey(ISSUER, "active");

        assertThat(first.publicKey().getEncoded())
                .isEqualTo(activeKey.toECPublicKey().getEncoded());
        assertThat(second.publicKey().getEncoded())
                .isEqualTo(activeKey.toECPublicKey().getEncoded());
        assertThat(resolver.fetchCount()).isEqualTo(1);
    }

    @Test
    void resolveSigningKey_refreshesWhenCachedKidHasExpired() throws Exception {
        ECKey expiredKey = new ECKeyGenerator(Curve.P_256).keyID("rollover").generate();
        ECKey refreshedKey = new ECKeyGenerator(Curve.P_256).keyID("rollover").generate();

        FakeResolver resolver = new FakeResolver(Duration.ofDays(1));
        resolver.stubMetadata(
                ISSUER,
                buildMetadata(
                        ISSUER,
                        buildJwks(expiredKey, Instant.now().minusSeconds(5).getEpochSecond())),
                Duration.ofHours(1));

        assertThatThrownBy(() -> resolver.resolveSigningKey(ISSUER, "rollover"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not contain a signing key");

        resolver.stubMetadata(
                ISSUER,
                buildMetadata(
                        ISSUER,
                        buildJwks(refreshedKey, Instant.now().plusSeconds(3600).getEpochSecond())),
                Duration.ofHours(1));

        JwtVcIssuerMetadataResolver.ResolvedIssuerKey resolved = resolver.resolveSigningKey(ISSUER, "rollover");

        assertThat(resolved.publicKey().getEncoded())
                .isEqualTo(refreshedKey.toECPublicKey().getEncoded());
        assertThat(resolver.fetchCount()).isEqualTo(2);
    }

    @Test
    void resolveSigningKey_capsCachingByConfiguredTtl() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("cap").generate();
        FakeResolver resolver = new FakeResolver(Duration.ofSeconds(5));
        resolver.stubMetadata(
                ISSUER,
                buildMetadata(
                        ISSUER, buildJwks(key, Instant.now().plusSeconds(3600).getEpochSecond())),
                Duration.ofHours(1));

        JwtVcIssuerMetadataResolver.ResolvedIssuerKey resolved = resolver.resolveSigningKey(ISSUER, "cap");

        assertThat(resolved.expiresAt()).isBeforeOrEqualTo(Instant.now().plusSeconds(5));
    }

    @Test
    void resolveSigningKey_buildsWellKnownUrlForIssuerPath() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-1").generate();
        FakeResolver resolver = new FakeResolver(Duration.ofDays(1));
        resolver.stubMetadata(
                ISSUER,
                buildMetadata(
                        ISSUER, buildJwks(key, Instant.now().plusSeconds(3600).getEpochSecond())),
                Duration.ofMinutes(10));

        resolver.resolveSigningKey(ISSUER, "kid-1");

        assertThat(resolver.lastFetchedUrl()).isEqualTo("https://issuer.example/.well-known/jwt-vc-issuer/tenant/123");
    }

    @Test
    void resolveSigningKey_followsJwksUriUsingKeycloakJwksPath() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("remote-kid").generate();
        FakeResolver resolver = new FakeResolver(Duration.ofDays(1));
        String jwksUri = "https://issuer.example/tenant/123/keys";
        resolver.stubMetadata(
                ISSUER,
                OBJECT_MAPPER.writeValueAsString(Map.of("issuer", ISSUER, "jwks_uri", jwksUri)),
                Duration.ofMinutes(10));
        resolver.stubJwks(
                jwksUri,
                OBJECT_MAPPER.writeValueAsString(
                        buildJwks(key, Instant.now().plusSeconds(3600).getEpochSecond())),
                Duration.ofMinutes(5));

        JwtVcIssuerMetadataResolver.ResolvedIssuerKey resolved = resolver.resolveSigningKey(ISSUER, "remote-kid");

        assertThat(resolved.publicKey().getEncoded())
                .isEqualTo(key.toECPublicKey().getEncoded());
        assertThat(resolver.remoteJwksFetchUsed()).isTrue();
        assertThat(resolver.fetchCount()).isEqualTo(2);
    }

    private static String buildMetadata(String issuer, Map<String, Object> jwks) throws Exception {
        return OBJECT_MAPPER.writeValueAsString(Map.of("issuer", issuer, "jwks", jwks));
    }

    private static Map<String, Object> buildJwks(ECKey key, long exp) {
        Map<String, Object> jwk = new HashMap<>(key.toPublicJWK().toJSONObject());
        jwk.put("exp", exp);
        return Map.of("keys", java.util.List.of(jwk));
    }

    private static final class FakeResolver extends JwtVcIssuerMetadataResolver {

        private final Map<String, FetchResult> documents = new HashMap<>();
        private int fetchCount;
        private String lastFetchedUrl;
        private boolean remoteJwksFetchUsed;

        private FakeResolver(Duration maxCacheTtl) {
            super(maxCacheTtl);
        }

        void stubMetadata(String issuer, String body, Duration cacheTtl) throws Exception {
            JsonNode json = OBJECT_MAPPER.readTree(body);
            documents.put(toWellKnown(issuer), new FetchResult(json, cacheTtl, Instant.now()));
        }

        void stubJwks(String url, String body, Duration cacheTtl) throws Exception {
            JsonNode json = OBJECT_MAPPER.readTree(body);
            documents.put(url, new FetchResult(json, cacheTtl, Instant.now()));
        }

        int fetchCount() {
            return fetchCount;
        }

        String lastFetchedUrl() {
            return lastFetchedUrl;
        }

        boolean remoteJwksFetchUsed() {
            return remoteJwksFetchUsed;
        }

        @Override
        protected FetchResult fetchJson(String url) {
            fetchCount++;
            lastFetchedUrl = url;
            FetchResult result = documents.get(url);
            if (result == null) {
                throw new IllegalStateException("No stub for " + url);
            }
            return result;
        }

        @Override
        protected org.keycloak.jose.jwk.JSONWebKeySet fetchRemoteJwks(String url, JsonNode fallbackJwksDocument)
                throws Exception {
            remoteJwksFetchUsed = true;
            return parseJsonWebKeySet(fallbackJwksDocument);
        }

        private static String toWellKnown(String issuer) {
            if (issuer.endsWith("/tenant/123")) {
                return "https://issuer.example/.well-known/jwt-vc-issuer/tenant/123";
            }
            return issuer;
        }
    }
}
