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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Map;
import java.util.UUID;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JWKUtil;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/** OID4VP EC JWK with explicit private-key support for response-encryption keys. */
public class Oid4vpJwk extends ECPublicJWK {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String PRIVATE_KEY_MEMBER = "d";
    private static final String JOSE_CURVE_P_256 = "P-256";
    private static final String JOSE_CURVE_P_384 = "P-384";
    private static final String JOSE_CURVE_P_521 = "P-521";
    private static final String JCA_CURVE_SECP256R1 = "secp256r1";
    private static final String JCA_CURVE_SECP384R1 = "secp384r1";
    private static final String JCA_CURVE_SECP521R1 = "secp521r1";

    @JsonProperty(PRIVATE_KEY_MEMBER)
    private String privateKey;

    public Oid4vpJwk() {
        setKeyType(KeyType.EC);
    }

    public Oid4vpJwk(String curve, String x, String y, String privateKey, String keyId, String algorithm, String use) {
        this();
        setCrv(curve);
        setX(x);
        setY(y);
        setPrivateKey(privateKey);
        setKeyId(keyId);
        setAlgorithm(algorithm);
        setPublicKeyUse(use);
    }

    public static Oid4vpJwk generate(String curve, String algorithm, String use) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(toJcaCurveName(curve)), SECURE_RANDOM);
            KeyPair keyPair = generator.generateKeyPair();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicJWK publicJwk = (ECPublicJWK) JWKBuilder.create()
                    .kid(UUID.randomUUID().toString())
                    .algorithm(algorithm)
                    .ec(publicKey, parseKeyUse(use));
            return new Oid4vpJwk(
                    publicJwk.getCrv(),
                    publicJwk.getX(),
                    publicJwk.getY(),
                    Base64Url.encode(JWKUtil.toIntegerBytes(
                            privateKey.getS(),
                            publicKey.getParams().getCurve().getField().getFieldSize())),
                    publicJwk.getKeyId(),
                    algorithm,
                    use);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate EC JWK", e);
        }
    }

    public static Oid4vpJwk parse(String jwkJson) {
        try {
            Oid4vpJwk jwk = JsonSerialization.readValue(jwkJson, Oid4vpJwk.class);
            validateEcKeyType(jwk);
            return jwk;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse EC JWK", e);
        }
    }

    public static Oid4vpJwk parse(Map<String, Object> map) {
        Oid4vpJwk jwk = JsonSerialization.mapper.convertValue(map, Oid4vpJwk.class);
        validateEcKeyType(jwk);
        return jwk;
    }

    public static String computeThumbprint(String jwkJson) {
        return computeThumbprint(JWKParser.create().parse(jwkJson).getJwk());
    }

    public String curve() {
        return getCrv();
    }

    public String x() {
        return getX();
    }

    public String y() {
        return getY();
    }

    public String privateKey() {
        return getPrivateKey();
    }

    public String keyId() {
        return getKeyId();
    }

    public String algorithm() {
        return getAlgorithm();
    }

    public String use() {
        return getPublicKeyUse();
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public boolean hasPrivateKey() {
        return privateKey != null && !privateKey.isBlank();
    }

    public ECPublicKey toPublicKey() {
        try {
            return (ECPublicKey) JWKParser.create(toPublicJwk()).toPublicKey();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to construct EC public key from JWK", e);
        }
    }

    public ECPrivateKey toPrivateKey() {
        if (!hasPrivateKey()) {
            throw new IllegalArgumentException("EC JWK does not contain a private key");
        }
        try {
            return (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new ECPrivateKeySpec(base64UrlUInt(privateKey), ecParameterSpec(curve())));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to construct EC private key from JWK", e);
        }
    }

    public Oid4vpJwk toPublicJwk() {
        return new Oid4vpJwk(curve(), x(), y(), null, keyId(), algorithm(), use());
    }

    public String toJson() {
        try {
            return JsonSerialization.writeValueAsString(this);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize EC JWK", e);
        }
    }

    public String thumbprint() {
        return computeThumbprint(toPublicJwk());
    }

    private static KeyUse parseKeyUse(String use) {
        return KeyUse.ENC.getSpecName().equalsIgnoreCase(use) ? KeyUse.ENC : KeyUse.SIG;
    }

    private static void validateEcKeyType(JWK jwk) {
        if (!KeyType.EC.equals(jwk.getKeyType())) {
            throw new IllegalArgumentException("Unsupported JWK key type: " + jwk.getKeyType());
        }
    }

    /** JOSE JWKs use `P-xxx` names while JCA EC APIs expect SEC curve names like `secp256r1`. */
    private static String toJcaCurveName(String joseCurve) {
        return switch (joseCurve) {
            case JOSE_CURVE_P_256 -> JCA_CURVE_SECP256R1;
            case JOSE_CURVE_P_384 -> JCA_CURVE_SECP384R1;
            case JOSE_CURVE_P_521 -> JCA_CURVE_SECP521R1;
            default -> throw new IllegalArgumentException("Unsupported EC curve: " + joseCurve);
        };
    }

    private static ECParameterSpec ecParameterSpec(String curve) {
        try {
            return CryptoIntegration.getProvider().createECParams(toJcaCurveName(curve));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize EC parameters", e);
        }
    }

    private static BigInteger base64UrlUInt(String value) {
        return new BigInteger(1, Base64Url.decode(value));
    }

    private static String computeThumbprint(JWK jwk) {
        validateEcKeyType(jwk);
        String thumbprint = JWKSUtils.computeThumbprint(jwk);
        if (thumbprint == null) {
            throw new IllegalStateException("Failed to compute JWK thumbprint");
        }
        return thumbprint;
    }
}
