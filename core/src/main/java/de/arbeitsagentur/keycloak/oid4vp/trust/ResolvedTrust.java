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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
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
 * @param hasDeclaredTrustSource    whether any trust material provider is configured. Derived from
 *                                  configuration, so it is the same whether or not the trust material
 *                                  is currently reachable: a credential type no provider serves and a
 *                                  declared source that resolves to no anchors (empty lists here) both
 *                                  make verification fail instead of falling back to trusting the
 *                                  issuer's own self-published metadata.
 */
public record ResolvedTrust(
        List<X509TrustMaterial> issuanceTrust,
        List<TrustedIssuerCertificate> directIssuerCertificates,
        List<TrustedIssuerKey> trustedIssuerKeys,
        List<X509Certificate> revocationCertificates,
        List<TrustedAuthority> trustedAuthorities,
        boolean hasDeclaredTrustSource) {

    public ResolvedTrust {
        issuanceTrust = List.copyOf(issuanceTrust);
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
        return validateIssuerChain(chain, null);
    }

    /**
     * Validates a credential issuer certificate chain for a credential of the given issuer and returns
     * the leaf key. When {@code issuer} is non-null (formats that name their issuer, such as SD-JWT),
     * only directly trusted certificates bound to that issuer satisfy the pinned fast path, and a chain
     * built to the PKIX anchors is additionally bound to the issuer through the leaf certificate's
     * subject alternative names, so a certificate trusted for one issuer cannot validate a credential
     * claiming another. When {@code issuer} is null (formats without an issuer identifier, such as
     * mDoc), every pinned certificate is eligible and the trust material's credential-type scope keeps
     * trust domains apart.
     *
     * <p>A chain whose leaf is itself one of the configured trust anchors is complete without path
     * building: the trust source pins that exact certificate, so only its validity window is
     * checked. Path building could never accept it anyway, because a leaf must be an end entity
     * certificate. This is how an mDoc signed directly by a trust listed self-signed document
     * signer certificate validates, such as the OpenID conformance suite's hard-coded mDL signer
     * (conformance-suite issue #1663).
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

        if (issuanceTrust.isEmpty()) {
            throw new VerificationException("No X.509 trust anchors available for certificate chain validation");
        }
        VerificationException firstFailure = null;
        for (X509TrustMaterial material : issuanceTrust) {
            try {
                X509CertificateChainValidator.validateCertificateChain(
                        chain, material.trustAnchors(), material.requiredExtendedKeyUsages());
                if (issuer != null) {
                    requireIssuerMatchesLeafSan(leaf, issuer);
                }
                return leaf.getPublicKey();
            } catch (VerificationException e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        throw firstFailure;
    }

    /** Whether the certificate is itself one of the configured PKIX trust anchors. */
    private boolean isTrustAnchor(X509Certificate certificate) {
        return issuanceTrust.stream()
                .anyMatch(material -> material.trustAnchors().contains(certificate));
    }

    /**
     * Binds the credential's {@code iss} to the validated leaf certificate: the value must appear as
     * a uniformResourceIdentifier subject alternative name of the leaf, or its host as a dNSName
     * entry for an HTTPS issuer. SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-13, section 3.5) identifies
     * the issuer of an x5c credential by the end-entity certificate; this check is how that
     * certificate and the {@code iss} claim are held together.
     */
    private static void requireIssuerMatchesLeafSan(X509Certificate leaf, String issuer) throws VerificationException {
        Collection<List<?>> subjectAlternativeNames;
        try {
            subjectAlternativeNames = leaf.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new VerificationException("The leaf certificate's subject alternative names are unreadable", e);
        }
        if (subjectAlternativeNames != null) {
            String issuerHost = hostOfHttpsUri(issuer);
            for (List<?> entry : subjectAlternativeNames) {
                if (entry.size() < 2 || !(entry.get(1) instanceof String name)) {
                    continue;
                }
                int type = entry.get(0) instanceof Integer i ? i : -1;
                if (type == 6 && name.equals(issuer)) {
                    return;
                }
                if (type == 2 && issuerHost != null && name.equalsIgnoreCase(issuerHost)) {
                    return;
                }
            }
        }
        throw new VerificationException("The credential issuer '" + issuer
                + "' does not match any subject alternative name of the validated leaf certificate");
    }

    private static String hostOfHttpsUri(String issuer) {
        try {
            URI uri = new URI(issuer);
            return "https".equalsIgnoreCase(uri.getScheme()) ? uri.getHost() : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }
}
