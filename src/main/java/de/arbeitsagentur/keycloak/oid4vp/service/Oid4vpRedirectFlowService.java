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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;

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
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class Oid4vpRedirectFlowService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRedirectFlowService.class);

    private final KeycloakSession session;

    public Oid4vpRedirectFlowService(KeycloakSession session) {
        this.session = Objects.requireNonNull(session);
    }

    public URI buildWalletAuthorizationUrl(String walletScheme, String clientId, URI requestUri) {
        String scheme = StringUtil.isNotBlank(walletScheme) ? walletScheme : DEFAULT_WALLET_SCHEME;
        if (!scheme.endsWith("://")) {
            scheme = scheme + "://";
        }

        StringBuilder url = new StringBuilder();
        url.append(scheme).append("?");
        url.append(OAuth2Constants.CLIENT_ID).append("=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
        url.append("&")
                .append(REQUEST_URI)
                .append("=")
                .append(URLEncoder.encode(requestUri.toString(), StandardCharsets.UTF_8));
        return URI.create(url.toString());
    }

    public SignedRequestObject buildSignedRequestObject(RequestObjectParams params) {

        ResolvedSigningKey resolved = resolveSigningMaterial(params.x509SigningKeyJwk());

        ECKey responseEncryptionKey = params.enforceHaip() ? createResponseEncryptionKey() : null;

        var claims = buildBaseClaims(
                params.clientId(),
                params.responseUri(),
                params.state(),
                params.nonce(),
                params.enforceHaip(),
                params.lifespanSeconds());
        if (StringUtil.isNotBlank(params.walletNonce())) {
            claims.put(WALLET_NONCE, params.walletNonce());
        }
        addClientMetadataClaim(claims, responseEncryptionKey);
        addDcqlAndVerifierInfo(claims, params.dcqlQuery(), params.verifierInfo());

        String jwt = signClaims(resolved, params.clientIdScheme(), params.x509CertPem(), claims);
        String encryptionKeyJson = responseEncryptionKey != null ? responseEncryptionKey.toJSONString() : null;
        return new SignedRequestObject(jwt, encryptionKeyJson);
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
        return new ResolvedSigningKey(null, resolveSigningKey());
    }

    private LinkedHashMap<String, Object> buildBaseClaims(
            String clientId, String responseUri, String state, String nonce, boolean enforceHaip, int lifespanSeconds) {
        Instant now = Instant.now();
        long issuedAt = now.getEpochSecond();
        long expiresAt = now.plusSeconds(lifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", clientId);
        claims.put("aud", SELF_ISSUED_V2);
        claims.put(OAuth2Constants.CLIENT_ID, clientId);
        claims.put(OAuth2Constants.RESPONSE_TYPE, RESPONSE_TYPE_VP_TOKEN);
        claims.put(
                OIDCLoginProtocol.RESPONSE_MODE_PARAM,
                enforceHaip ? RESPONSE_MODE_DIRECT_POST_JWT : RESPONSE_MODE_DIRECT_POST);
        claims.put(RESPONSE_URI, responseUri);
        claims.put(OIDCLoginProtocol.NONCE_PARAM, nonce);
        claims.put(OAuth2Constants.STATE, state);
        return claims;
    }

    private void addClientMetadataClaim(LinkedHashMap<String, Object> claims, ECKey encryptionKey) {
        if (encryptionKey == null) return;
        claims.put(CLIENT_METADATA, buildClientMetadata(encryptionKey));
    }

    private void addDcqlAndVerifierInfo(LinkedHashMap<String, Object> claims, String dcqlQuery, String verifierInfo) {
        if (StringUtil.isNotBlank(dcqlQuery)) {
            claims.put(DCQL_QUERY, parseJsonClaim(dcqlQuery));
        }
        if (StringUtil.isNotBlank(verifierInfo)) {
            Object parsed = parseJsonClaim(verifierInfo);
            if (parsed != null) {
                claims.put(VERIFIER_INFO, parsed);
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

    public String computeX509SanDnsClientId(String pemCertificate) {
        try {
            X509Certificate cert = decodeFirstCertificate(pemCertificate);
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        return CLIENT_ID_SCHEME_X509_SAN_DNS + ":" + san.get(1);
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
            X509Certificate cert = decodeFirstCertificate(pemCertificate);
            byte[] encoded = cert.getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            String hashBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return CLIENT_ID_SCHEME_X509_HASH + ":" + hashBase64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute certificate hash", e);
        }
    }

    private X509Certificate decodeFirstCertificate(String pem) {
        X509Certificate[] certs = PemUtils.decodeCertificates(pem);
        if (certs == null || certs.length == 0) {
            throw new IllegalStateException("No certificates found in PEM");
        }
        return certs[0];
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
        } else if ((CLIENT_ID_SCHEME_X509_SAN_DNS.equals(clientIdScheme)
                        || CLIENT_ID_SCHEME_X509_HASH.equals(clientIdScheme))
                && x509CertPem != null
                && !x509CertPem.isBlank()) {
            X509Certificate cert = decodeFirstCertificate(x509CertPem);
            builder = builder.x5c(List.of(cert));
        } else if (signingKey.getPublicKey() != null) {
            builder = builder.jwk(toPublicJwk(signingKey));
        }

        return builder.jsonContent(claims).sign(new AsymmetricSignatureSignerContext(signingKey));
    }

    private KeyWrapper resolveSigningKey() {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("Missing realm context");
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
            LOG.tracef("Generated ephemeral encryption key: kid=%s, jwk=\n%s", key.getKeyID(), key.toJSONString());
            return key;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Map<String, Object> buildClientMetadata(ECKey responseEncryptionKey) {
        ECKey publicKey = responseEncryptionKey.toPublicJWK();
        Map<String, Object> jwk = new LinkedHashMap<>(publicKey.toJSONObject());
        jwk.put("alg", JWEAlgorithm.ECDH_ES.getName());
        jwk.put("use", "enc");

        var vpFormats = new LinkedHashMap<String, Object>();
        vpFormats.put(
                FORMAT_SD_JWT_VC, Map.of("sd-jwt_alg_values", List.of("ES256"), "kb-jwt_alg_values", List.of("ES256")));
        vpFormats.put(FORMAT_MSO_MDOC, Map.of("alg", List.of("ES256")));

        var meta = new LinkedHashMap<String, Object>();
        meta.put("jwks", Map.of("keys", List.of(jwk)));
        meta.put("encrypted_response_alg_values_supported", List.of(JWEAlgorithm.ECDH_ES.getName()));
        meta.put(
                "encrypted_response_enc_values_supported",
                List.of(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));
        meta.put("vp_formats_supported", vpFormats);
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

    private Object parseJsonClaim(String json) {
        if (StringUtil.isBlank(json)) {
            return null;
        }
        try {
            return JsonSerialization.readValue(json, Object.class);
        } catch (Exception e) {
            return json;
        }
    }
}
