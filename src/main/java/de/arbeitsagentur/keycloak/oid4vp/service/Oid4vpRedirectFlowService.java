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
package de.arbeitsagentur.keycloak.oid4vp.service;

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
import de.arbeitsagentur.keycloak.oid4vp.domain.RebuildParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
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
import org.keycloak.utils.StringUtil;

public class Oid4vpRedirectFlowService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRedirectFlowService.class);
    private static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    private final KeycloakSession session;
    private final ObjectMapper objectMapper;

    public Oid4vpRedirectFlowService(KeycloakSession session, ObjectMapper objectMapper) {
        this.session = Objects.requireNonNull(session);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    public URI buildWalletAuthorizationUrl(String walletScheme, String clientId, URI requestUri) {
        String scheme = StringUtil.isNotBlank(walletScheme) ? walletScheme : "openid4vp://";
        if (!scheme.endsWith("://")) {
            scheme = scheme + "://";
        }

        StringBuilder url = new StringBuilder();
        url.append(scheme).append("?");
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

        ResolvedSigningKey resolved = resolveSigningMaterial(x509SigningKeyJwk);

        ECKey responseEncryptionKey = parseOrCreateEncryptionKey(existingEncryptionKeyJson);

        var claims = buildBaseClaims(clientId, responseUri, state, nonce, lifespanSeconds);
        addClientMetadataClaim(claims, responseEncryptionKey);
        addDcqlAndVerifierInfo(claims, dcqlQuery, verifierInfo);

        String jwt = signClaims(resolved, clientIdScheme, x509CertPem, claims);
        return new SignedRequestObject(jwt, responseEncryptionKey.toJSONString(), state, nonce);
    }

    public SignedRequestObject rebuildWithWalletNonce(
            RebuildParams rebuildParams, String state, String nonce, String walletNonce, int lifespanSeconds) {

        ResolvedSigningKey resolved = resolveSigningMaterial(rebuildParams.x509SigningKeyJwk());

        ECKey encryptionKey = parseEncryptionKey(rebuildParams.encryptionPublicKeyJson());

        var claims = buildBaseClaims(
                rebuildParams.effectiveClientId(), rebuildParams.responseUri(), state, nonce, lifespanSeconds);
        claims.put("wallet_nonce", walletNonce);
        addClientMetadataClaim(claims, encryptionKey);
        addDcqlAndVerifierInfo(claims, rebuildParams.dcqlQuery(), rebuildParams.verifierInfo());

        String jwt = signClaims(resolved, rebuildParams.clientIdScheme(), rebuildParams.x509CertPem(), claims);
        return new SignedRequestObject(jwt, null, state, nonce);
    }

    private record ResolvedSigningKey(ECKey ecKey, KeyWrapper keycloakKey) {
        boolean useNimbus() {
            return ecKey != null;
        }
    }

    private ResolvedSigningKey resolveSigningMaterial(String x509SigningKeyJwk) {
        if (StringUtil.isNotBlank(x509SigningKeyJwk)) {
            try {
                return new ResolvedSigningKey(ECKey.parse(x509SigningKeyJwk), null);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        }
        return new ResolvedSigningKey(null, resolveSigningKey(null));
    }

    private LinkedHashMap<String, Object> buildBaseClaims(
            String clientId, String responseUri, String state, String nonce, int lifespanSeconds) {
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
        return claims;
    }

    private void addClientMetadataClaim(LinkedHashMap<String, Object> claims, ECKey encryptionKey) {
        if (encryptionKey == null) return;
        Map<String, Object> clientMeta = buildClientMetadata(encryptionKey);
        if (!clientMeta.isEmpty()) {
            claims.put("client_metadata", clientMeta);
        }
    }

    private void addDcqlAndVerifierInfo(LinkedHashMap<String, Object> claims, String dcqlQuery, String verifierInfo) {
        if (StringUtil.isNotBlank(dcqlQuery)) {
            claims.put("dcql_query", parseJsonClaim(dcqlQuery));
        }
        if (StringUtil.isNotBlank(verifierInfo)) {
            Object parsed = parseJsonClaim(verifierInfo);
            if (parsed != null) {
                claims.put("verifier_info", parsed);
            }
        }
    }

    private String signClaims(
            ResolvedSigningKey resolved,
            String clientIdScheme,
            String x509CertPem,
            LinkedHashMap<String, Object> claims) {
        try {
            if (resolved.useNimbus()) {
                return signWithNimbus(resolved.ecKey(), claims);
            }
            return signWithKeycloak(resolved.keycloakKey(), clientIdScheme, x509CertPem, claims);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign request object", e);
        }
    }

    private ECKey parseOrCreateEncryptionKey(String existingEncryptionKeyJson) {
        if (StringUtil.isNotBlank(existingEncryptionKeyJson)) {
            try {
                return ECKey.parse(existingEncryptionKeyJson);
            } catch (Exception e) {
                // Fall through to create new key
            }
        }
        return createResponseEncryptionKey();
    }

    private ECKey parseEncryptionKey(String encryptionPublicKeyJson) {
        if (encryptionPublicKeyJson == null) return null;
        try {
            return ECKey.parse(encryptionPublicKeyJson);
        } catch (Exception e) {
            LOG.warnf("Failed to parse encryption key: %s", e.getMessage());
            return null;
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
        if (StringUtil.isNotBlank(preferredKid)) {
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
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
            LOG.tracef("Generated ephemeral encryption key: kid=%s, jwk=%s", key.getKeyID(), key.toJSONString());
            return key;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Map<String, Object> buildClientMetadata(ECKey responseEncryptionKey) {
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
        if (StringUtil.isBlank(json)) {
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
}
