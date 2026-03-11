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
package de.arbeitsagentur.keycloak.oid4vp.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpJwk;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JWKUtil;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/** Parses and serializes configured signing JWKs into Keycloak {@link KeyWrapper} instances. */
public final class Oid4vpSigningKeyParser {

    private static final String PRIVATE_KEY_MEMBER = "d";

    private Oid4vpSigningKeyParser() {}

    public static KeyWrapper parse(String jwkJson) {
        try {
            JWK jwk = JWKParser.create().parse(jwkJson).getJwk();
            return switch (jwk.getKeyType()) {
                case KeyType.EC -> buildEcKeyWrapper(JsonSerialization.mapper.convertValue(jwk, EcPrivateJwk.class));
                case KeyType.RSA -> buildRsaKeyWrapper(JsonSerialization.mapper.convertValue(jwk, RsaPrivateJwk.class));
                default -> throw new IllegalArgumentException("Unsupported signing JWK key type: " + jwk.getKeyType());
            };
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse signing JWK", e);
        }
    }

    public static String serialize(PublicKey publicKey, PrivateKey privateKey, List<X509Certificate> certificateChain) {
        try {
            JWK signingJwk =
                    switch (publicKey) {
                        case ECPublicKey ecPublicKey -> createEcSigningJwk(ecPublicKey, privateKey, certificateChain);
                        case RSAPublicKey rsaPublicKey ->
                            createRsaSigningJwk(rsaPublicKey, privateKey, certificateChain);
                        default ->
                            throw new IllegalArgumentException(
                                    "Unsupported certificate key type: " + publicKey.getAlgorithm());
                    };
            signingJwk.setKeyId(computeKid(signingJwk));
            return JsonSerialization.writeValueAsString(signingJwk);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize signing JWK", e);
        }
    }

    public static String extractKid(String jwkJson) {
        try {
            return JWKParser.create().parse(jwkJson).getJwk().getKeyId();
        } catch (Exception e) {
            return null;
        }
    }

    private static EcPrivateJwk createEcSigningJwk(
            ECPublicKey publicKey, PrivateKey privateKey, List<X509Certificate> certificateChain) {
        if (!(privateKey instanceof ECPrivateKey ecPrivateKey)) {
            throw new IllegalArgumentException("Unsupported certificate key pair");
        }
        ECPublicJWK publicJwk = (ECPublicJWK) JWKBuilder.create().ec(publicKey, certificateChain, KeyUse.SIG);
        EcPrivateJwk jwk = JsonSerialization.mapper.convertValue(publicJwk, EcPrivateJwk.class);
        jwk.setPrivateKey(Base64Url.encode(JWKUtil.toIntegerBytes(
                ecPrivateKey.getS(), publicKey.getParams().getCurve().getField().getFieldSize())));
        return jwk;
    }

    private static RsaPrivateJwk createRsaSigningJwk(
            RSAPublicKey publicKey, PrivateKey privateKey, List<X509Certificate> certificateChain) {
        if (!(privateKey instanceof RSAPrivateKey rsaPrivateKey)) {
            throw new IllegalArgumentException("Unsupported certificate key pair");
        }
        RSAPublicJWK publicJwk = (RSAPublicJWK) JWKBuilder.create().rsa(publicKey, certificateChain, KeyUse.SIG);
        RsaPrivateJwk jwk = JsonSerialization.mapper.convertValue(publicJwk, RsaPrivateJwk.class);
        jwk.setPrivateKey(Base64Url.encode(JWKUtil.toIntegerBytes(rsaPrivateKey.getPrivateExponent())));
        return jwk;
    }

    private static KeyWrapper buildEcKeyWrapper(EcPrivateJwk jwk) throws Exception {
        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        if (keyWrapper == null) {
            throw new IllegalArgumentException("Unsupported signing JWK key type: " + jwk.getKeyType());
        }
        keyWrapper.setKid(defaultKid(jwk.getKeyId(), JWKSUtils.computeThumbprint(jwk)));
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setCurve(jwk.getCrv());
        keyWrapper.setAlgorithm(keyWrapper.getAlgorithmOrDefault());
        keyWrapper.setPrivateKey(Oid4vpJwk.parse(JsonSerialization.mapper.convertValue(jwk, java.util.Map.class))
                .toPrivateKey());
        attachCertificateChain(keyWrapper, jwk);
        return keyWrapper;
    }

    private static KeyWrapper buildRsaKeyWrapper(RsaPrivateJwk jwk) throws Exception {
        BigInteger modulus = new BigInteger(1, Base64Url.decode(jwk.getModulus()));
        BigInteger privateExponent = new BigInteger(1, Base64Url.decode(jwk.getPrivateKey()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        if (keyWrapper == null) {
            throw new IllegalArgumentException("Unsupported signing JWK key type: " + jwk.getKeyType());
        }
        keyWrapper.setKid(defaultKid(jwk.getKeyId(), computeKid(jwk)));
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setAlgorithm(keyWrapper.getAlgorithmOrDefault());
        keyWrapper.setPrivateKey(keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent)));
        attachCertificateChain(keyWrapper, jwk);
        return keyWrapper;
    }

    private static void attachCertificateChain(KeyWrapper keyWrapper, JWK jwk) throws Exception {
        List<X509Certificate> chain = parseX5cChain(jwk);
        if (!chain.isEmpty()) {
            keyWrapper.setCertificateChain(chain);
            keyWrapper.setCertificate(chain.get(0));
        }
    }

    private static List<X509Certificate> parseX5cChain(JWK jwk) throws Exception {
        String[] x5c = jwk.getX509CertificateChain();
        if (x5c == null || x5c.length == 0) {
            return List.of();
        }
        List<X509Certificate> chain = new ArrayList<>(x5c.length);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        for (String certificate : x5c) {
            byte[] der = Base64.getMimeDecoder().decode(certificate);
            chain.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(der)));
        }
        return chain;
    }

    private static String computeKid(JWK jwk) {
        String thumbprint = JWKSUtils.computeThumbprint(jwk);
        if (thumbprint == null) {
            throw new IllegalStateException("Failed to compute JWK thumbprint");
        }
        return thumbprint;
    }

    private static String defaultKid(String kid, String fallback) {
        return kid != null ? kid : fallback;
    }

    private static final class EcPrivateJwk extends ECPublicJWK {

        @JsonProperty(PRIVATE_KEY_MEMBER)
        private String privateKey;

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }

    private static final class RsaPrivateJwk extends RSAPublicJWK {

        @JsonProperty(PRIVATE_KEY_MEMBER)
        private String privateKey;

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }
}
