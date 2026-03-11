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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import de.arbeitsagentur.keycloak.oid4vp.util.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectSigner;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Builds OID4VP authorization request claims and wallet redirect URLs.
 *
 * <p>Handles the request-object part of Phase 1 of the OID4VP flow: it assembles request claims,
 * client metadata, verifier info, and response-encryption key material, then delegates compact JWS
 * creation to {@code Oid4vpRequestObjectSigner}. Optional request-object encryption based on
 * wallet metadata happens later in {@code Oid4vpRequestObjectService} via
 * {@code Oid4vpRequestObjectEncryptor}.
 *
 * <p>Supports both Keycloak realm signing keys and external X.509 signing keys,
 * and computes client IDs for {@code x509_san_dns} and {@code x509_hash} schemes.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5 — Authorization Request</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1">OID4VP 1.0 §5.1 — Signed Authorization Request</a>
 */
public class Oid4vpRedirectFlowService {

    private static final Logger LOG = Logger.getLogger(Oid4vpRedirectFlowService.class);

    private final KeycloakSession session;
    private final int requestObjectLifespanSeconds;
    private final Oid4vpRequestObjectSigner requestObjectSigner;

    public Oid4vpRedirectFlowService(KeycloakSession session, int requestObjectLifespanSeconds) {
        this.session = Objects.requireNonNull(session);
        this.requestObjectLifespanSeconds = requestObjectLifespanSeconds;
        this.requestObjectSigner = new Oid4vpRequestObjectSigner();
    }

    /** Builds the wallet authorization URL with {@code client_id} and {@code request_uri} parameters. */
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

    /**
     * Builds request-object claims from the given parameters and signs them as a compact JWS.
     * When the effective response mode is {@code direct_post.jwt}, also generates or reuses the
     * ephemeral response-encryption key advertised in {@code client_metadata}.
     */
    public SignedRequestObject buildSignedRequestObject(RequestObjectParams params) {
        KeyWrapper signingKey = resolveSigningKey(params.x509SigningKeyJwk());
        Oid4vpJwk responseEncryptionKey = resolveResponseEncryptionKey(params);
        LinkedHashMap<String, Object> claims = buildRequestObjectClaims(params, responseEncryptionKey);
        String jwt = signRequestObject(signingKey, params.clientIdScheme(), params.x509CertPem(), claims);
        String encryptionKeyJson = responseEncryptionKey != null ? responseEncryptionKey.toJson() : null;
        return new SignedRequestObject(jwt, encryptionKeyJson);
    }

    private Oid4vpJwk resolveResponseEncryptionKey(RequestObjectParams params) {
        if (!params.responseMode().requiresEncryption()) {
            return null;
        }
        if (StringUtil.isNotBlank(params.responseEncryptionKeyJson())) {
            try {
                return Oid4vpJwk.parse(params.responseEncryptionKeyJson());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse request handle encryption key", e);
            }
        }
        return createResponseEncryptionKey();
    }

    private LinkedHashMap<String, Object> buildRequestObjectClaims(
            RequestObjectParams params, Oid4vpJwk responseEncryptionKey) {
        Instant now = Instant.now();
        long issuedAt = now.getEpochSecond();
        long expiresAt = now.plusSeconds(requestObjectLifespanSeconds).getEpochSecond();

        var claims = new LinkedHashMap<String, Object>();
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", issuedAt);
        claims.put("exp", expiresAt);
        claims.put("iss", params.clientId());
        claims.put("aud", SELF_ISSUED_V2);
        claims.put(OAuth2Constants.CLIENT_ID, params.clientId());
        boolean includeIdToken = params.useIdTokenSubject() && !params.enforceHaip();
        claims.put(OAuth2Constants.RESPONSE_TYPE, includeIdToken ? RESPONSE_TYPE_VP_TOKEN_ID_TOKEN : VP_TOKEN);
        if (includeIdToken) {
            claims.put(OAuth2Constants.SCOPE, "openid");
        }
        claims.put(OIDCLoginProtocol.RESPONSE_MODE_PARAM, params.responseMode().parameterValue());
        claims.put(RESPONSE_URI, params.responseUri());
        claims.put(OIDCLoginProtocol.NONCE_PARAM, params.nonce());
        claims.put(OAuth2Constants.STATE, params.state());
        if (StringUtil.isNotBlank(params.walletNonce())) {
            claims.put(WALLET_NONCE, params.walletNonce());
        }
        if (responseEncryptionKey != null) {
            claims.put(CLIENT_METADATA, buildClientMetadata(responseEncryptionKey));
        }
        addDcqlAndVerifierInfo(claims, params.dcqlQuery(), params.verifierInfo());
        return claims;
    }

    private void addDcqlAndVerifierInfo(LinkedHashMap<String, Object> claims, String dcqlQuery, String verifierInfo) {
        if (StringUtil.isNotBlank(dcqlQuery)) {
            claims.put(DCQL_QUERY, parseDcqlQueryClaim(dcqlQuery));
        }
        if (StringUtil.isNotBlank(verifierInfo)) {
            Object parsed = parseJsonClaim(verifierInfo);
            if (parsed != null) {
                claims.put(VERIFIER_INFO, parsed);
            }
        }
    }

    private String signRequestObject(
            KeyWrapper signingKey, String clientIdScheme, String x509CertPem, LinkedHashMap<String, Object> claims) {
        try {
            return requestObjectSigner.sign(
                    signingKey, Oid4vpClientIdScheme.resolve(clientIdScheme), x509CertPem, claims);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign request object", e);
        }
    }

    private KeyWrapper resolveSigningKey(String x509SigningKeyJwk) {
        if (StringUtil.isNotBlank(x509SigningKeyJwk)) {
            try {
                return requestObjectSigner.parseSigningKey(x509SigningKeyJwk);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse x509 signing key JWK", e);
            }
        }
        return resolveRealmSigningKey();
    }

    /** Computes a {@code x509_san_dns:<dns-name>} client ID from the certificate's SAN DNS entry. */
    private KeyWrapper resolveRealmSigningKey() {
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

    public Oid4vpJwk createResponseEncryptionKey() {
        try {
            Oid4vpJwk key = Oid4vpJwk.generate("P-256", "ECDH-ES", "enc");
            LOG.tracef("Generated ephemeral encryption key: kid=%s, jwk=\n%s", key.keyId(), key.toJson());
            return key;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    private Map<String, Object> buildClientMetadata(Oid4vpJwk responseEncryptionKey) {
        Map<String, Object> jwk =
                parseJsonObject(responseEncryptionKey.toPublicJwk().toJson());

        var vpFormats = new LinkedHashMap<String, Object>();
        vpFormats.put(
                FORMAT_SD_JWT_VC,
                Map.of(
                        "sd-jwt_alg_values", SUPPORTED_SD_JWT_ALG_VALUES,
                        "kb-jwt_alg_values", SUPPORTED_SD_JWT_ALG_VALUES));
        vpFormats.put(
                FORMAT_MSO_MDOC,
                Map.of(
                        "issuerauth_alg_values", SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES,
                        "deviceauth_alg_values", SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES));

        var meta = new LinkedHashMap<String, Object>();
        meta.put("jwks", Map.of("keys", List.of(jwk)));
        meta.put("encrypted_response_enc_values_supported", SUPPORTED_VERIFIER_RESPONSE_ENCRYPTION_METHOD_VALUES);
        meta.put("vp_formats_supported", vpFormats);
        return meta;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonObject(String json) {
        try {
            return JsonSerialization.readValue(json, Map.class);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse generated JWK JSON", e);
        }
    }

    private Object parseDcqlQueryClaim(String json) {
        Object parsed = parseJsonClaim(json);
        if (parsed instanceof Map<?, ?> dcqlQuery) {
            DcqlQueryBuilder.normalizeParsedQuery(dcqlQuery, Oid4vpTrustedAuthoritiesMode.NONE, null, List.of());
        }
        return parsed;
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
