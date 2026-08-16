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

import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.VerificationException;

/**
 * Trust material aggregated from the trust material identity providers that serve one credential.
 *
 * @param issuanceTrust             X.509 trust anchors and policy for credential issuer chains
 *                                  (SD-JWT x5c, mDoc x5chain)
 * @param directIssuerCertificates  end entity certificates listed as issuance services whose keys
 *                                  are trusted directly when a credential carries no chain, each
 *                                  bound to the issuer it is trusted for
 * @param trustedIssuerKeys         trusted issuer keys from providers that expose keys instead of
 *                                  X.509 anchors, each bound to the issuer it is trusted for
 * @param revocationCertificates    certificates of status list (revocation) services
 * @param trustedAuthorities        the DCQL {@code trusted_authorities} entries these providers
 *                                  advertise for the credential
 */
public record ResolvedTrust(
        List<X509TrustMaterial> issuanceTrust,
        List<TrustedIssuerCertificate> directIssuerCertificates,
        List<TrustedIssuerKey> trustedIssuerKeys,
        List<X509Certificate> revocationCertificates,
        List<TrustedAuthority> trustedAuthorities) {

    public ResolvedTrust {
        issuanceTrust = List.copyOf(issuanceTrust);
        directIssuerCertificates = List.copyOf(directIssuerCertificates);
        trustedIssuerKeys = List.copyOf(trustedIssuerKeys);
        revocationCertificates = List.copyOf(revocationCertificates);
        trustedAuthorities = List.copyOf(trustedAuthorities);
    }

    public static ResolvedTrust empty() {
        return new ResolvedTrust(List.of(), List.of(), List.of(), List.of(), List.of());
    }

    public boolean hasIssuerTrust() {
        return hasX509Trust() || !trustedIssuerKeys.isEmpty();
    }

    /** Whether a presented certificate chain can be validated against this trust material. */
    public boolean hasX509Trust() {
        return !issuanceTrust.isEmpty() || !directIssuerCertificates.isEmpty();
    }

    /** Whether a presented certificate chain can be built to an anchor of this trust material. */
    public boolean hasCertificateChainAnchors() {
        return !issuanceTrust.isEmpty();
    }

    /**
     * Whether a credential without a certificate chain can be verified: pinned issuer certificates
     * and published issuer keys both identify the issuer key directly. Providers exposing them make
     * a chainless credential a configured case rather than a missing chain.
     */
    public boolean hasChainlessIssuerTrust() {
        return !directIssuerCertificates.isEmpty() || !trustedIssuerKeys.isEmpty();
    }

    /**
     * Whether an issuer key route is configured for this credential. Providers that publish keys
     * make the {@code kid} route legitimate, so discovering keys from the credential's own issuer
     * metadata is not needed.
     */
    public boolean hasIssuerKeyTrust() {
        return !trustedIssuerKeys.isEmpty();
    }

    /** The trusted keys usable for a credential of the given issuer and JOSE {@code kid}. */
    public List<TrustedIssuerKey> issuerKeysFor(String issuer, String keyId) {
        return trustedIssuerKeys.stream()
                .filter(key -> key.trustedFor(issuer))
                .filter(key -> key.matchesKeyId(keyId))
                .toList();
    }

    /**
     * The directly trusted certificates usable for a credential of the given issuer. Used where a
     * credential names no certificate and its bare key is taken on trust, which is the case that
     * needs the issuer to match.
     */
    public List<X509Certificate> issuerCertificatesFor(String issuer) {
        return directIssuerCertificates.stream()
                .filter(certificate -> certificate.trustedFor(issuer))
                .map(TrustedIssuerCertificate::certificate)
                .toList();
    }

    /**
     * Every directly trusted certificate, whichever issuer it belongs to. Used where a credential
     * presents the certificate itself, so matching it is already the stronger statement, and by the
     * formats that have no issuer identifier to match against.
     */
    public List<X509Certificate> pinnedCertificates() {
        return directIssuerCertificates.stream()
                .map(TrustedIssuerCertificate::certificate)
                .toList();
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
        if (pinnedCertificates().contains(leaf)) {
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
