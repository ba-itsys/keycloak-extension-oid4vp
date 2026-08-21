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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves an ETSI TS 119 602 trust list of PID providers over HTTP.
 *
 * <p>Tests point the trust material identity provider at this server to run with a trust list that
 * does not list the wallet's credential issuer, so the DCQL {@code trusted_authorities} constraint
 * the verifier derives from it cannot be satisfied by any credential the wallet holds.
 *
 * <p>The server binds all interfaces because both parties fetching the list reach it differently:
 * Keycloak runs on the host, the wallet runs in a container where {@code localhost} resolves to the
 * Docker host gateway.
 */
public final class TestTrustListServer implements AutoCloseable {

    private static final String PATH = "/trust-list";
    private static final String PID_ISSUANCE_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String PID_REVOCATION_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Revocation";
    private static final Duration VALIDITY = Duration.ofHours(24);

    private final HttpServer server;

    private TestTrustListServer(HttpServer server) {
        this.server = server;
    }

    /** Starts a server listing the given certificates as PID issuance and revocation services. */
    public static TestTrustListServer serving(X509Certificate... certificates) {
        try {
            String trustListJwt = buildTrustListJwt(List.of(certificates));
            HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
            server.createContext(PATH, exchange -> respondWithTrustList(exchange, trustListJwt));
            server.start();
            return new TestTrustListServer(server);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to start the trust list server", e);
        }
    }

    /** The trust list URL, resolvable from the Keycloak server and from the wallet container. */
    public String url() {
        return "http://localhost:%d%s".formatted(server.getAddress().getPort(), PATH);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static void respondWithTrustList(HttpExchange exchange, String trustListJwt) throws IOException {
        byte[] body = trustListJwt.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/jwt");
        // Neither Keycloak nor the wallet may serve a later test from a cached copy of this list
        exchange.getResponseHeaders().add("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream responseBody = exchange.getResponseBody()) {
            responseBody.write(body);
        }
    }

    private static String buildTrustListJwt(List<X509Certificate> certificates) throws Exception {
        KeyPair signingKeyPair = TestCertificates.generateEcKeyPair();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                new JWTClaimsSet.Builder()
                        .claim("LoTE", listOfTrustedEntities(certificates))
                        .build());
        jwt.sign(new ECDSASigner((ECPrivateKey) signingKeyPair.getPrivate()));
        return jwt.serialize();
    }

    private static Map<String, Object> listOfTrustedEntities(List<X509Certificate> certificates) {
        // ETSI TS 119 602 V1.1.1 clause 6.1.3 writes date-times to the second and without a
        // decimal fraction, so the served list carries the times a real one would.
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        Map<String, Object> listAndSchemeInformation = new LinkedHashMap<>();
        listAndSchemeInformation.put("ListIssueDateTime", now.toString());
        listAndSchemeInformation.put("LoTESequenceNumber", 1);
        listAndSchemeInformation.put("LoTEType", TestWallet.PID_PROVIDERS_LOTE_TYPE);
        listAndSchemeInformation.put("LoTEVersionIdentifier", 1);
        listAndSchemeInformation.put("NextUpdate", now.plus(VALIDITY).toString());
        listAndSchemeInformation.put("SchemeTerritory", "EU");

        Map<String, Object> trustedEntity = Map.of(
                "TrustedEntityServices",
                List.of(
                        service(PID_ISSUANCE_SERVICE_TYPE, "PID Issuance Service", certificates),
                        service(PID_REVOCATION_SERVICE_TYPE, "PID Revocation Service", certificates)));

        Map<String, Object> listOfTrustedEntities = new LinkedHashMap<>();
        listOfTrustedEntities.put("ListAndSchemeInformation", listAndSchemeInformation);
        listOfTrustedEntities.put("TrustedEntitiesList", List.of(trustedEntity));
        return listOfTrustedEntities;
    }

    private static Map<String, Object> service(
            String serviceTypeIdentifier, String serviceName, List<X509Certificate> certificates) {
        List<Map<String, String>> encodedCertificates = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            encodedCertificates.add(Map.of("val", encode(certificate)));
        }

        Map<String, Object> serviceInformation = new LinkedHashMap<>();
        serviceInformation.put("ServiceDigitalIdentity", Map.of("X509Certificates", encodedCertificates));
        serviceInformation.put("ServiceName", List.of(Map.of("lang", "en-US", "value", serviceName)));
        serviceInformation.put("ServiceTypeIdentifier", serviceTypeIdentifier);
        return Map.of("ServiceInformation", serviceInformation);
    }

    private static String encode(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode trust list certificate", e);
        }
    }
}
