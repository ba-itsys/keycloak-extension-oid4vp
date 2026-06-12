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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.REQUEST_OBJECT_TYP;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.utils.StringUtil;

/** Signs OID4VP request object claims as a compact JWS using Keycloak's key abstractions. */
public final class Oid4vpRequestObjectSigner {

    public String sign(
            KeyWrapper signingKey,
            Oid4vpClientIdScheme clientIdScheme,
            String x509CertPem,
            LinkedHashMap<String, Object> claims) {
        JWSBuilder builder = new JWSBuilder().type(REQUEST_OBJECT_TYP).kid(signingKey.getKid());

        if (signingKey.getCertificateChain() != null
                && !signingKey.getCertificateChain().isEmpty()) {
            builder = builder.x5c(signingKey.getCertificateChain());
        } else if (clientIdScheme.isCertificateBound() && StringUtil.isNotBlank(x509CertPem)) {
            builder = builder.x5c(List.of(decodeFirstCertificate(x509CertPem)));
        } else if (signingKey.getPublicKey() != null) {
            builder = addPublicJwkHeader(builder, signingKey);
        }

        return builder.jsonContent(claims).sign(createSignerContext(signingKey));
    }

    public KeyWrapper parseSigningKey(String jwkJson) {
        return Oid4vpSigningKeyParser.parse(jwkJson);
    }

    private static X509Certificate decodeFirstCertificate(String pem) {
        X509Certificate[] certs = PemUtils.decodeCertificates(pem);
        if (certs == null || certs.length == 0) {
            throw new IllegalStateException("No certificates found in PEM");
        }
        return certs[0];
    }

    private static JWSBuilder addPublicJwkHeader(JWSBuilder builder, KeyWrapper key) {
        JWKBuilder jwkBuilder = JWKBuilder.create().kid(key.getKid()).algorithm(key.getAlgorithmOrDefault());
        String publicKeyAlgorithm = key.getPublicKey().getAlgorithm();
        if ("RSA".equalsIgnoreCase(publicKeyAlgorithm)) {
            return builder.jwk(jwkBuilder.rsa(key.getPublicKey(), KeyUse.SIG));
        }
        if ("EC".equalsIgnoreCase(publicKeyAlgorithm)) {
            return builder.jwk(jwkBuilder.ec(key.getPublicKey(), KeyUse.SIG));
        }
        throw new IllegalStateException("Unsupported signing key algorithm: " + publicKeyAlgorithm);
    }

    private static SignatureSignerContext createSignerContext(KeyWrapper signingKey) {
        try {
            if ("EC".equalsIgnoreCase(signingKey.getType())) {
                return new ECDSASignatureSignerContext(signingKey);
            }
            return new AsymmetricSignatureSignerContext(signingKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create signer context", e);
        }
    }
}
