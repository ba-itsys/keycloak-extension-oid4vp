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

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * Validates x5c certificate chains against a set of trusted CA certificates.
 * Shared by SD-JWT, mDoc, and status list signature verification.
 */
final class X5cChainValidator {

    private static final Logger LOG = Logger.getLogger(X5cChainValidator.class);

    private X5cChainValidator() {}

    /**
     * Parses Base64-encoded x5c certificates, walks the chain verifying signatures,
     * and checks that the top of the chain is signed by one of the trusted certificates.
     *
     * @return the leaf certificate's public key
     * @throws Exception if the chain is invalid or not anchored by a trusted certificate
     */
    static PublicKey validateChain(List<String> x5c, List<X509Certificate> trustedCertificates) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        List<X509Certificate> chain = new ArrayList<>();
        for (String certB64 : x5c) {
            byte[] certDer = Base64.getDecoder().decode(certB64);
            chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
        }

        return validateCertChain(chain, trustedCertificates);
    }

    /**
     * Validates a pre-parsed certificate chain against trusted certificates.
     *
     * @return the leaf certificate's public key
     * @throws Exception if the chain is invalid or not anchored by a trusted certificate
     */
    static PublicKey validateCertChain(List<X509Certificate> chain, List<X509Certificate> trustedCertificates)
            throws Exception {
        if (chain.isEmpty()) {
            throw new IllegalStateException("Empty x5c chain");
        }

        X509Certificate leaf = chain.get(0);
        LOG.debugf("x5c leaf certificate: %s", leaf.getSubjectX500Principal().getName());

        // Walk up the chain: each cert should be signed by the next one
        for (int i = 0; i < chain.size() - 1; i++) {
            chain.get(i).verify(chain.get(i + 1).getPublicKey());
        }

        // The top of the chain must be signed by one of the trusted certificates
        X509Certificate topOfChain = chain.get(chain.size() - 1);
        for (X509Certificate trusted : trustedCertificates) {
            try {
                topOfChain.verify(trusted.getPublicKey());
                LOG.debugf(
                        "x5c chain anchored by trusted certificate: %s",
                        trusted.getSubjectX500Principal().getName());
                return leaf.getPublicKey();
            } catch (Exception ignored) {
                // Try next trusted certificate
            }
        }

        throw new IllegalStateException("x5c chain not anchored by any trusted certificate");
    }
}
