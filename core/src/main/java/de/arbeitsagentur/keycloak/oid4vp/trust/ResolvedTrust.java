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
package de.arbeitsagentur.keycloak.oid4vp.trust;

import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jwk.JWK;

/**
 * Trust material aggregated from the trust material identity providers referenced by an OID4VP
 * identity provider.
 *
 * @param issuanceTrust             X.509 trust anchors and policy for credential issuer chains
 *                                  (SD-JWT x5c, mDoc x5chain)
 * @param directIssuerCertificates  end entity certificates listed as issuance services whose keys
 *                                  are trusted directly when a credential carries no chain
 * @param trustedIssuerJwks         trusted issuer JWKs from providers that expose keys instead of
 *                                  X.509 anchors
 * @param revocationCertificates    certificates of status list (revocation) services
 * @param authorityKeyIdentifiers   certificate key identifiers for DCQL {@code trusted_authorities}
 *                                  entries of type {@code aki}
 * @param trustListUrls             trust list URLs for DCQL {@code trusted_authorities} entries of
 *                                  type {@code etsi_tl}
 */
public record ResolvedTrust(
        List<X509TrustMaterial> issuanceTrust,
        List<X509Certificate> directIssuerCertificates,
        List<JWK> trustedIssuerJwks,
        List<X509Certificate> revocationCertificates,
        List<String> authorityKeyIdentifiers,
        List<String> trustListUrls) {

    public ResolvedTrust {
        issuanceTrust = List.copyOf(issuanceTrust);
        directIssuerCertificates = List.copyOf(directIssuerCertificates);
        trustedIssuerJwks = List.copyOf(trustedIssuerJwks);
        revocationCertificates = List.copyOf(revocationCertificates);
        authorityKeyIdentifiers = List.copyOf(authorityKeyIdentifiers);
        trustListUrls = List.copyOf(trustListUrls);
    }

    public static ResolvedTrust empty() {
        return new ResolvedTrust(List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    public boolean hasIssuerTrust() {
        return !issuanceTrust.isEmpty() || !directIssuerCertificates.isEmpty() || !trustedIssuerJwks.isEmpty();
    }

    /**
     * Validates a credential issuer certificate chain and returns the leaf key. A chain whose leaf
     * is a directly trusted issuer certificate is accepted after a validity check; otherwise the
     * chain must build a PKIX path to the anchors of one of the issuance trust materials,
     * honoring that material's extended key usage policy.
     */
    public PublicKey validateIssuerChain(List<X509Certificate> chain) throws VerificationException {
        if (chain.isEmpty()) {
            throw new VerificationException("The x5c certificate chain is empty");
        }
        X509Certificate leaf = chain.get(0);
        if (directIssuerCertificates.contains(leaf)) {
            try {
                leaf.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new VerificationException("The pinned issuer certificate is not currently valid", e);
            }
            return leaf.getPublicKey();
        }

        if (issuanceTrust.isEmpty()) {
            throw new VerificationException("No X.509 trust anchors available for certificate chain validation");
        }
        VerificationException lastFailure = null;
        for (X509TrustMaterial material : issuanceTrust) {
            try {
                X509CertificateChainValidator.validateCertificateChain(
                        chain, material.trustAnchors(), material.requiredExtendedKeyUsages());
                return leaf.getPublicKey();
            } catch (VerificationException e) {
                lastFailure = e;
            }
        }
        throw lastFailure;
    }
}
