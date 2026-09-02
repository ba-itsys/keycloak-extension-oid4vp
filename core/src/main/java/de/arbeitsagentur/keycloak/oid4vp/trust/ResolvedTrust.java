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
 * @param directIssuerCertificates  end entity certificates listed as issuance services. Their keys
 *                                  are trusted directly when a credential carries no chain. Each is
 *                                  bound to the issuer it is trusted for.
 * @param trustedIssuerKeys         trusted issuer keys from providers that expose keys instead of
 *                                  X.509 anchors, each bound to the issuer it is trusted for
 * @param hasDeclaredTrustSource    whether any trust material provider is configured. This is
 *                                  derived from configuration alone, so it holds whether or not the
 *                                  trust material is currently reachable. A credential type no
 *                                  provider serves and a declared source that resolves to no
 *                                  anchors both leave the lists empty and make verification fail
 *                                  instead of falling back to the issuer's own self-published
 *                                  metadata.
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

    /** Returns whether a presented certificate chain can be validated against this trust material. */
    public boolean hasX509Trust() {
        return !issuanceTrust.isEmpty() || !directIssuerCertificates.isEmpty();
    }

    public boolean hasCertificateChainAnchors() {
        return !issuanceTrust.isEmpty();
    }

    /**
     * Returns whether a credential without a certificate chain can be verified. Pinned issuer
     * certificates and published issuer keys both identify the issuer key directly, so a provider
     * exposing either makes a chainless credential a configured case rather than a missing chain.
     */
    public boolean hasChainlessIssuerTrust() {
        return !directIssuerCertificates.isEmpty() || !trustedIssuerKeys.isEmpty();
    }

    /**
     * Returns whether an issuer key route is configured for this credential. A provider that
     * publishes keys makes the {@code kid} route legitimate, so keys need not be discovered from
     * the credential's own issuer metadata.
     */
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
     * Returns the directly trusted certificates usable for a credential of the given issuer. This
     * serves the case where a credential names no certificate and its bare key is taken on trust,
     * which is exactly where the issuer has to match.
     */
    public List<X509Certificate> issuerCertificatesFor(String issuer) {
        return directIssuerCertificates.stream()
                .filter(certificate -> certificate.trustedFor(issuer))
                .map(TrustedIssuerCertificate::certificate)
                .toList();
    }

    /**
     * Returns every directly trusted certificate, whichever issuer it belongs to. This serves the
     * case where a credential presents the certificate itself, because matching the certificate is
     * the stronger statement, and the formats that have no issuer identifier to match against.
     */
    public List<X509Certificate> pinnedCertificates() {
        return directIssuerCertificates.stream()
                .map(TrustedIssuerCertificate::certificate)
                .toList();
    }

    /**
     * Validates a credential issuer certificate chain and returns the leaf key. A chain whose leaf
     * is a directly trusted issuer certificate is accepted after a validity check. Otherwise the
     * chain must build a PKIX path to the anchors of one of the issuance trust materials. That
     * material's extended key usage policy applies.
     */
    public PublicKey validateIssuerChain(List<X509Certificate> chain) throws VerificationException {
        return validateIssuerChain(chain, null);
    }

    /**
     * Validates a credential issuer certificate chain for a credential of the given issuer and
     * returns the leaf key.
     *
     * <p>A non-null {@code issuer} comes from formats that name their issuer, such as SD-JWT. Only
     * directly trusted certificates bound to that issuer satisfy the pinned fast path. A chain built
     * to the PKIX anchors is bound to the issuer as well, through the subject alternative names of
     * the leaf certificate. A certificate trusted for one issuer can therefore not validate a
     * credential claiming another.
     *
     * <p>A null {@code issuer} comes from formats without an issuer identifier, such as mDoc. Every
     * pinned certificate is then eligible, and the credential type scope of the trust material is
     * what keeps the trust domains apart. A chain whose leaf is itself one of the configured trust
     * anchors is complete without path building: the trust source pins that exact certificate, so
     * only its validity window is checked, and path building could never accept it anyway because a
     * leaf must be an end entity certificate. An mDoc signed directly by a trust listed self-signed
     * document signer certificate validates this way.
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

    private boolean isTrustAnchor(X509Certificate certificate) {
        return issuanceTrust.stream()
                .anyMatch(material -> material.trustAnchors().contains(certificate));
    }

    /**
     * Binds the credential's {@code iss} to the validated leaf certificate. The value must appear
     * as a uniformResourceIdentifier subject alternative name of the leaf. For an HTTPS issuer its
     * host may appear as a dNSName entry instead. SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-13,
     * section 3.5) identifies the issuer of an x5c credential by the end entity certificate. This
     * check holds that certificate and the {@code iss} claim together.
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
