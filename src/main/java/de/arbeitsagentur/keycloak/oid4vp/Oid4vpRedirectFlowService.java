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
package de.arbeitsagentur.keycloak.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class Oid4vpRedirectFlowService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRedirectFlowService.class);
    private static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    private final KeycloakSession session;
    private final ObjectMapper objectMapper;

    public Oid4vpRedirectFlowService(KeycloakSession session, ObjectMapper objectMapper) {
        this.session = Objects.requireNonNull(session);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    public URI buildWalletAuthorizationUrl(String walletBaseUrl, String walletScheme, String clientId, URI requestUri) {
        StringBuilder url = new StringBuilder();
        if (walletBaseUrl != null && !walletBaseUrl.isBlank() && walletBaseUrl.startsWith("http")) {
            url.append(walletBaseUrl);
            url.append(walletBaseUrl.contains("?") ? "&" : "?");
        } else {
            String scheme = walletScheme != null && !walletScheme.isBlank() ? walletScheme : "openid4vp://";
            if (!scheme.endsWith("://")) {
                scheme = scheme + "://";
            }
            url.append(scheme).append("?");
        }

        url.append("client_id=").append(urlEncode(clientId));
        url.append("&request_uri=").append(urlEncode(requestUri.toString()));
        return URI.create(url.toString());
    }

    public SignedRequestObject buildSignedRequestObject(
            String dcqlQuery,
            String verifierInfo,
            String clientId,
            String clientIdScheme,
            String responseUri,
            String state,
            String nonce,
            String x509CertPem,
            String x509SigningKeyJwk,
            String existingEncryptionKeyJson,
            int lifespanSeconds) {

        ECKey ecSigningKey = null;
        KeyWrapper signingKey = null;
        boolean useNimbusSigning = false;

        if (x509SigningKeyJwk != null && !x509SigningKeyJwk.isBlank()) {
            try {
                ecSigningKey = ECKey.parse(x509SigningKeyJwk);
                useNimbusSigning = true;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        } else {
            signingKey = resolveSigningKey(null);
        }

        ECKey responseEncryptionKey;
        if (existingEncryptionKeyJson != null && !existingEncryptionKeyJson.isBlank()) {
            try {
                responseEncryptionKey = ECKey.parse(existingEncryptionKeyJson);
            } catch (Exception e) {
                responseEncryptionKey = createResponseEncryptionKey();
            }
        } else {
            responseEncryptionKey = createResponseEncryptionKey();
        }

        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = Instant.now().plusSeconds(lifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", clientId);
        claims.put("aud", "https://self-issued.me/v2");
        claims.put("client_id", clientId);
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "direct_post.jwt");
        claims.put("response_uri", responseUri);
        claims.put("nonce", nonce);
        claims.put("state", state);

        Object clientMeta = buildClientMetadata(responseEncryptionKey);
        if (clientMeta != null && !((Map<?, ?>) clientMeta).isEmpty()) {
            claims.put("client_metadata", clientMeta);
        }

        if (dcqlQuery != null && !dcqlQuery.isBlank()) {
            claims.put("dcql_query", parseJsonClaim(dcqlQuery));
        }
        if (verifierInfo != null && !verifierInfo.isBlank()) {
            Object parsed = parseJsonClaim(verifierInfo);
            if (parsed != null) {
                claims.put("verifier_info", parsed);
            }
        }

        try {
            String jwt;
            if (useNimbusSigning && ecSigningKey != null) {
                jwt = signWithNimbus(ecSigningKey, claims);
            } else {
                jwt = signWithKeycloak(signingKey, clientIdScheme, x509CertPem, claims);
            }
            return new SignedRequestObject(jwt, responseEncryptionKey.toJSONString(), state, nonce);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign request object", e);
        }
    }

    public SignedRequestObject rebuildWithWalletNonce(
            Oid4vpRequestObjectStore.RebuildParams rebuildParams,
            String state,
            String nonce,
            String walletNonce,
            int lifespanSeconds) {

        String effectiveClientId = rebuildParams.effectiveClientId();
        String clientIdScheme = rebuildParams.clientIdScheme();
        String responseUri = rebuildParams.responseUri();

        ECKey ecSigningKey = null;
        KeyWrapper signingKey = null;
        boolean useNimbusSigning = false;

        if (rebuildParams.x509SigningKeyJwk() != null
                && !rebuildParams.x509SigningKeyJwk().isBlank()) {
            try {
                ecSigningKey = ECKey.parse(rebuildParams.x509SigningKeyJwk());
                useNimbusSigning = true;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        } else {
            signingKey = resolveSigningKey(null);
        }

        ECKey encryptionKey = null;
        if (rebuildParams.encryptionPublicKeyJson() != null) {
            try {
                encryptionKey = ECKey.parse(rebuildParams.encryptionPublicKeyJson());
            } catch (Exception e) {
                LOG.warnf("Failed to parse encryption key: %s", e.getMessage());
            }
        }

        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = Instant.now().plusSeconds(lifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", effectiveClientId);
        claims.put("aud", "https://self-issued.me/v2");
        claims.put("client_id", effectiveClientId);
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "direct_post.jwt");
        claims.put("response_uri", responseUri);
        claims.put("nonce", nonce);
        claims.put("state", state);
        claims.put("wallet_nonce", walletNonce);

        if (encryptionKey != null) {
            Object clientMeta = buildClientMetadata(encryptionKey);
            if (clientMeta != null && !((Map<?, ?>) clientMeta).isEmpty()) {
                claims.put("client_metadata", clientMeta);
            }
        }

        if (rebuildParams.dcqlQuery() != null && !rebuildParams.dcqlQuery().isBlank()) {
            claims.put("dcql_query", parseJsonClaim(rebuildParams.dcqlQuery()));
        }
        if (rebuildParams.verifierInfo() != null
                && !rebuildParams.verifierInfo().isBlank()) {
            Object parsed = parseJsonClaim(rebuildParams.verifierInfo());
            if (parsed != null) {
                claims.put("verifier_info", parsed);
            }
        }

        try {
            String jwt;
            if (useNimbusSigning && ecSigningKey != null) {
                jwt = signWithNimbus(ecSigningKey, claims);
            } else {
                jwt = signWithKeycloak(signingKey, clientIdScheme, rebuildParams.x509CertPem(), claims);
            }
            return new SignedRequestObject(jwt, null, state, nonce);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign rebuilt request object", e);
        }
    }

    public String computeX509SanDnsClientId(String pemCertificate) {
        try {
            X509Certificate cert = parsePemCertificate(pemCertificate);
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        return "x509_san_dns:" + san.get(1);
                    }
                }
            }
            throw new IllegalStateException("No DNS SAN found in certificate");
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract DNS SAN from certificate", e);
        }
    }

    public String computeX509HashClientId(String pemCertificate) {
        try {
            X509Certificate cert = parsePemCertificate(pemCertificate);
            byte[] encoded = cert.getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            String hashBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return "x509_hash:" + hashBase64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute certificate hash", e);
        }
    }

    private String signWithNimbus(ECKey ecSigningKey, LinkedHashMap<String, Object> claims) throws Exception {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(REQUEST_OBJECT_TYP))
                .keyID(ecSigningKey.getKeyID());

        if (ecSigningKey.getX509CertChain() != null
                && !ecSigningKey.getX509CertChain().isEmpty()) {
            headerBuilder.x509CertChain(ecSigningKey.getX509CertChain());
        }

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        for (var entry : claims.entrySet()) {
            claimsBuilder.claim(entry.getKey(), entry.getValue());
        }

        SignedJWT signedJwt = new SignedJWT(headerBuilder.build(), claimsBuilder.build());
        signedJwt.sign(new ECDSASigner(ecSigningKey));
        return signedJwt.serialize();
    }

    private String signWithKeycloak(
            KeyWrapper signingKey, String clientIdScheme, String x509CertPem, LinkedHashMap<String, Object> claims)
            throws Exception {
        JWSBuilder builder = new JWSBuilder().type(REQUEST_OBJECT_TYP).kid(signingKey.getKid());

        if (signingKey.getCertificateChain() != null
                && !signingKey.getCertificateChain().isEmpty()) {
            builder = builder.x5c(signingKey.getCertificateChain());
        } else if (("x509_san_dns".equals(clientIdScheme) || "x509_hash".equals(clientIdScheme))
                && x509CertPem != null
                && !x509CertPem.isBlank()) {
            X509Certificate cert = parsePemCertificate(x509CertPem);
            builder = builder.x5c(List.of(cert));
        } else if (signingKey.getPublicKey() != null) {
            builder = builder.jwk(toPublicJwk(signingKey));
        }

        return builder.jsonContent(claims).sign(new AsymmetricSignatureSignerContext(signingKey));
    }

    private KeyWrapper resolveSigningKey(String preferredKid) {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("Missing realm context");
        }
        if (preferredKid != null && !preferredKid.isBlank()) {
            return session.keys()
                    .getKeysStream(realm)
                    .filter(key -> preferredKid.equals(key.getKid()))
                    .filter(key -> KeyUse.SIG.equals(key.getUse()))
                    .filter(key -> key.getPrivateKey() != null)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Signing key not found: kid=" + preferredKid));
        }
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, realm.getDefaultSignatureAlgorithm());
        if (key == null) {
            throw new IllegalStateException("No active realm signing key found");
        }
        return key;
    }

    private ECKey createResponseEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Object buildClientMetadata(ECKey responseEncryptionKey) {
        var meta = new LinkedHashMap<String, Object>();
        if (responseEncryptionKey != null) {
            ECKey publicKey = responseEncryptionKey.toPublicJWK();
            Map<String, Object> jwk = new LinkedHashMap<>(publicKey.toJSONObject());
            jwk.put("alg", JWEAlgorithm.ECDH_ES.getName());
            jwk.put("use", "enc");
            meta.put("jwks", Map.of("keys", List.of(jwk)));
            meta.put(
                    "encrypted_response_enc_values_supported",
                    List.of(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));
            var vpFormats = new LinkedHashMap<String, Object>();
            vpFormats.put(
                    "dc+sd-jwt", Map.of("sd-jwt_alg_values", List.of("ES256"), "kb-jwt_alg_values", List.of("ES256")));
            vpFormats.put("mso_mdoc", Map.of("alg", List.of("ES256")));
            meta.put("vp_formats_supported", vpFormats);
        }
        return meta;
    }

    private JWK toPublicJwk(KeyWrapper key) {
        String algorithm = key.getAlgorithmOrDefault();
        JWKBuilder builder = JWKBuilder.create().kid(key.getKid()).algorithm(algorithm);
        String pubAlg = key.getPublicKey().getAlgorithm();
        if ("RSA".equalsIgnoreCase(pubAlg)) {
            return builder.rsa(key.getPublicKey(), KeyUse.SIG);
        }
        if ("EC".equalsIgnoreCase(pubAlg)) {
            return builder.ec(key.getPublicKey(), KeyUse.SIG);
        }
        throw new IllegalStateException("Unsupported signing key algorithm: " + pubAlg);
    }

    private X509Certificate parsePemCertificate(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    private Object parseJsonClaim(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return json;
        }
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record SignedRequestObject(String jwt, String encryptionKeyJson, String state, String nonce) {}
}
