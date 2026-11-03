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
import de.arbeitsagentur.keycloak.oid4vp.util.FailureDetails;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.X509CertificateChainValidator;

/**
 * Holds the trust material of the identity providers that serve one credential.
 * {@code hasDeclaredTrustSource} comes from the configuration alone, so it holds even when the trust
 * material is unreachable. A credential type no provider serves and a declared source without
 * anchors both leave the lists empty. Verification then fails and does not fall back to the metadata
 * the issuer publishes itself.
 */
public record ResolvedTrust(
        List<IssuerTrustAnchors> issuerTrustAnchors,
        List<TrustedIssuerCertificate> directIssuerCertificates,
        List<TrustedIssuerKey> trustedIssuerKeys,
        List<X509Certificate> revocationCertificates,
        List<TrustedAuthority> trustedAuthorities,
        boolean hasDeclaredTrustSource) {

    public ResolvedTrust {
        issuerTrustAnchors = List.copyOf(issuerTrustAnchors);
        directIssuerCertificates = List.copyOf(directIssuerCertificates);
        trustedIssuerKeys = List.copyOf(trustedIssuerKeys);
        revocationCertificates = List.copyOf(revocationCertificates);
        trustedAuthorities = List.copyOf(trustedAuthorities);
    }

    public static ResolvedTrust empty() {
        return new ResolvedTrust(List.of(), List.of(), List.of(), List.of(), List.of(), false);
    }

    public boolean hasIssuerTrust() {
        return hasX509Trust() || !trustedIssuerKeys.isEmpty();
    }

    public boolean hasX509Trust() {
        return !issuerTrustAnchors.isEmpty() || !directIssuerCertificates.isEmpty();
    }

    public boolean hasCertificateChainAnchors() {
        return !issuerTrustAnchors.isEmpty();
    }

    public boolean hasChainlessIssuerTrust() {
        return !directIssuerCertificates.isEmpty() || !trustedIssuerKeys.isEmpty();
    }

    public boolean hasIssuerKeyTrust() {
        return !trustedIssuerKeys.isEmpty();
    }

    public List<TrustedIssuerKey> issuerKeysFor(String issuer, String keyId) {
        return trustedIssuerKeys.stream()
                .filter(key -> key.trustedFor(issuer))
                .filter(key -> key.matchesKeyId(keyId))
                .toList();
    }

    /**
     * Returns the directly trusted certificates usable for a credential of the given issuer. A
     * chainless credential depends on this match, because nothing else ties the bare key to the
     * credential.
     */
    public List<X509Certificate> issuerCertificatesFor(String issuer) {
        return directIssuerCertificates.stream()
                .filter(certificate -> certificate.trustedFor(issuer))
                .map(TrustedIssuerCertificate::certificate)
                .toList();
    }

    /**
     * Returns every directly trusted certificate, whichever issuer it belongs to. Serves credentials
     * that present the certificate itself, because a matching certificate is the stronger statement.
     * Also serves formats that have no issuer identifier to match against.
     */
    public List<X509Certificate> pinnedCertificates() {
        return directIssuerCertificates.stream()
                .map(TrustedIssuerCertificate::certificate)
                .toList();
    }

    public PublicKey validateIssuerChain(List<X509Certificate> chain) throws VerificationException {
        return validateIssuerChain(chain, null);
    }

    /**
     * Validates a credential issuer certificate chain for a credential of the given issuer and
     * returns the leaf key.
     *
     * <p>For SD-JWT, {@code issuer} is the credential's iss value. A pinned certificate configured
     * for a specific issuer is eligible only when that value matches. A chain validated against
     * CA certificates identifies its signer through the subject of the leaf certificate
     * (SD-JWT VC draft 13, section 3.5).
     *
     * <p>Formats without an issuer identifier, such as mDoc, pass null. Any pinned certificate
     * in the trust material for that credential type is then eligible. A leaf that is itself a
     * configured trust anchor is accepted after checking its validity period. The trust source
     * already trusts that exact certificate, so a path to another CA is unnecessary. This includes
     * self signed mDoc document signer certificates on a trust list.
     */
    public PublicKey validateIssuerChain(List<X509Certificate> chain, String issuer) throws VerificationException {
        if (chain.isEmpty()) {
            throw new VerificationException("The x5c certificate chain is empty");
        }
        X509Certificate leaf = chain.get(0);
        List<X509Certificate> pinned = issuer != null ? issuerCertificatesFor(issuer) : pinnedCertificates();
        if (pinned.contains(leaf) || (issuer == null && isTrustAnchor(leaf))) {
            try {
                leaf.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new VerificationException("The pinned issuer certificate is not currently valid", e);
            }
            return leaf.getPublicKey();
        }

        if (issuerTrustAnchors.isEmpty()) {
            throw new VerificationException("No X.509 trust anchors available for certificate chain validation");
        }
        List<String> x5c = chain.stream().map(PemUtils::encodeCertificate).toList();
        VerificationException firstFailure = null;
        for (IssuerTrustAnchors material : issuerTrustAnchors) {
            try {
                X509CertificateChainValidator.validate(
                        x5c, null, material.trustAnchors(), material.requiredExtendedKeyUsages());
                return leaf.getPublicKey();
            } catch (VerificationException e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        throw new VerificationException(
                FailureDetails.causeChain(firstFailure) + " (chain=" + FailureDetails.certificates(chain) + ")",
                firstFailure);
    }

    private boolean isTrustAnchor(X509Certificate certificate) {
        return issuerTrustAnchors.stream()
                .anyMatch(material -> material.trustAnchors().contains(certificate));
    }
}
