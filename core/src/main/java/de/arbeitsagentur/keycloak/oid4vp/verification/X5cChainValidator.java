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

import de.arbeitsagentur.keycloak.oid4vp.trust.X509CertificateChainValidator;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/**
 * JWT signature verification against pinned trusted certificates, used for trust list and status
 * list JWTs.
 *
 * <p>A presented x5c chain is accepted when its leaf is one of the trusted certificates (pinned)
 * or when it builds a PKIX path to a trusted CA certificate via
 * {@link X509CertificateChainValidator}. Without a usable x5c chain, the signature is verified
 * directly against each trusted certificate's key.
 */
public final class X5cChainValidator {

    private static final Logger LOG = Logger.getLogger(X5cChainValidator.class);

    private X5cChainValidator() {}

    static JWSInput parseJwt(String compactJwt) {
        try {
            return new JWSInput(compactJwt);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse compact JWS/JWT", e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseClaims(JWSInput jwt) {
        try {
            return JsonSerialization.readValue(jwt.getContent(), Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT claims", e);
        }
    }

    static void verifyJwtSignature(JWSInput jwt, PublicKey publicKey) throws Exception {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(publicKey);
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setAlgorithm(jwt.getHeader().getRawAlgorithm());
        keyWrapper.setType(resolveKeyType(publicKey));

        SignatureVerifierContext verifier = KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
        if (!verifier.verify(jwt.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII), jwt.getSignature())) {
            throw new IllegalArgumentException("JWT signature verification failed");
        }
    }

    /**
     * Returns the leaf key of an x5c chain whose leaf is pinned in the trusted certificates or
     * that builds a PKIX path to a trusted CA certificate.
     */
    static PublicKey validateChain(List<String> x5c, List<X509Certificate> trustedCertificates) throws Exception {
        List<X509Certificate> chain = X509CertificateChainValidator.decodeCertificateChain(x5c);
        X509Certificate leaf = chain.get(0);
        LOG.debugf("x5c leaf certificate: %s", leaf.getSubjectX500Principal().getName());

        if (trustedCertificates.contains(leaf)) {
            leaf.checkValidity();
            LOG.debug("x5c leaf certificate is a pinned trusted certificate");
            return leaf.getPublicKey();
        }

        List<X509Certificate> anchors = trustedCertificates.stream()
                .filter(X5cChainValidator::isCaCertificate)
                .toList();
        if (anchors.isEmpty()) {
            throw new IllegalStateException("x5c chain not anchored by any trusted certificate");
        }
        X509CertificateChainValidator.validateCertificateChain(chain, anchors, List.of());
        return leaf.getPublicKey();
    }

    /** Returns whether the certificate is a CA certificate usable for certificate signing. */
    public static boolean isCaCertificate(X509Certificate certificate) {
        if (certificate.getBasicConstraints() < 0) {
            return false;
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage == null || (keyUsage.length > 5 && keyUsage[5]);
    }

    public static void validateConfiguredVerifierChain(List<X509Certificate> chain) throws Exception {
        if (chain.isEmpty()) {
            throw new IllegalStateException("Verifier x5c chain is empty");
        }

        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            try {
                certificate.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new IllegalStateException(
                        "Verifier certificate at position " + i + " has expired: "
                                + certificate.getSubjectX500Principal().getName(),
                        e);
            } catch (CertificateNotYetValidException e) {
                throw new IllegalStateException(
                        "Verifier certificate at position " + i + " is not yet valid: "
                                + certificate.getSubjectX500Principal().getName(),
                        e);
            }
        }

        X509Certificate leaf = chain.get(0);
        if (leaf.getBasicConstraints() >= 0) {
            throw new IllegalStateException("HAIP verifier leaf certificate must not be a CA certificate");
        }

        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate certificate = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (issuer.getBasicConstraints() < 0) {
                throw new IllegalStateException(
                        "Verifier certificate issuer at position " + (i + 1) + " is not a CA certificate");
            }
            certificate.verify(issuer.getPublicKey());
        }

        X509Certificate top = chain.get(chain.size() - 1);
        if (top.getBasicConstraints() < 0) {
            throw new IllegalStateException("Verifier x5c top certificate must be a CA certificate");
        }
        if (chain.size() == 1) {
            throw new IllegalStateException("HAIP requires x509_hash verifier certificates to be CA-issued");
        }
    }

    static void verifyJwtSignature(String compactJwt, List<X509Certificate> trustedCerts) throws Exception {
        JWSInput jwt = parseJwt(compactJwt);

        List<String> x5c = jwt.getHeader().getX5c();
        if (x5c == null) {
            x5c = List.of();
        }
        if (!x5c.isEmpty()) {
            try {
                PublicKey leafKey = validateChain(x5c, trustedCerts);
                verifyJwtSignature(jwt, leafKey);
                LOG.debug("JWT signature verified via x5c chain");
                return;
            } catch (Exception e) {
                LOG.debugf("JWT x5c chain validation failed: %s", e.getMessage());
            }
        }

        for (X509Certificate cert : trustedCerts) {
            try {
                verifyJwtSignature(jwt, cert.getPublicKey());
                LOG.debug("JWT signature verified with trusted key");
                return;
            } catch (Exception e) {
            }
        }

        throw new IllegalStateException("JWT signature verification failed: no trusted key matched");
    }

    private static String resolveKeyType(PublicKey publicKey) {
        return switch (publicKey.getAlgorithm()) {
            case "EC", "ECDSA" -> KeyType.EC;
            case "RSA" -> KeyType.RSA;
            case "EdDSA", "Ed25519", "Ed448" -> KeyType.OKP;
            default ->
                throw new IllegalArgumentException("Unsupported signature key type: " + publicKey.getAlgorithm());
        };
    }
}
