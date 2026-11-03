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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.X509CertificateChainValidator;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trust material identity provider contract of this extension, extending the upstream JWK and X.509
 * surfaces with revocation (status list) trust, directly trusted issuer certificates for pinned or
 * chainless credentials, the credential types the provider serves, and the DCQL
 * {@code trusted_authorities} entries it can advertise. Every method defaults to empty, so a
 * provider implements only the surfaces it serves, as upstream does.
 */
public interface Oid4vpTrustMaterialIdentityProvider<C extends IdentityProviderModel>
        extends TrustMaterialIdentityProvider<C> {

    /**
     * Returns the PKIX trust anchors and policy for issuer certificate chains. The default adapts
     * the upstream {@code resolveX509Trust} method. Providers whose anchors may be intermediate CAs
     * override this, because the upstream record only accepts self-signed roots.
     */
    default List<IssuerTrustAnchors> issuerTrustAnchors() {
        return resolveX509Trust(TrustMaterialRequest.builder().build())
                .map(material -> new IssuerTrustAnchors(
                        material.trustAnchors(),
                        material.requiredExtendedKeyUsages(),
                        new CrlPolicy(getConfig().getInternalId(), null, CrlPolicy.DEFAULT.maxCacheTtl(), false)))
                .toList();
    }

    /**
     * Returns the end entity certificates trusted directly. Their keys verify credentials that carry
     * no certificate chain. A presented chain whose leaf equals one of these certificates is trusted
     * without path building.
     */
    default List<X509Certificate> directIssuerCertificates() {
        return List.of();
    }

    default List<X509Certificate> revocationCertificates() {
        return List.of();
    }

    /**
     * Returns the credential types (SD-JWT VCT, mDoc doctype) this provider is trusted for. An empty
     * list means it serves every credential type.
     */
    default List<String> servedCredentialTypes() {
        return List.of();
    }

    /**
     * Returns the DCQL {@code trusted_authorities} entries this provider can advertise for the
     * credentials it serves. The verifier never configures these centrally, because only the
     * provider knows whether it is backed by a trust list, by certificate key identifiers, or by
     * issuer keys that cannot be advertised at all.
     */
    default List<TrustedAuthority> trustedAuthorities() {
        return List.of();
    }

    /**
     * Returns the trusted issuer keys together with the issuer they belong to. Providers that
     * publish keys instead of X.509 anchors implement this instead of {@link #issuerTrustAnchors}.
     * The default adapts the upstream {@code resolveKeys} method, whose keys carry no issuer and
     * are therefore trusted for any issuer.
     */
    default List<TrustedIssuerKey> trustedIssuerKeys() {
        return resolveKeys(TrustMaterialRequest.builder().build())
                .map(TrustedIssuerKey::ofAnyIssuer)
                .toList();
    }

    /**
     * Returns the directly trusted issuer certificates together with the issuer they belong to, the
     * counterpart of {@link #trustedIssuerKeys()}. The default adapts
     * {@link #directIssuerCertificates()}, whose certificates carry no issuer because trust list
     * entries name services. A provider that knows the issuer of its certificates overrides this,
     * so those certificates cannot verify a credential that claims another issuer.
     */
    default List<TrustedIssuerCertificate> trustedIssuerCertificates() {
        return directIssuerCertificates().stream()
                .map(TrustedIssuerCertificate::ofAnyIssuer)
                .toList();
    }

    /**
     * Validates a certificate chain with the rules the extension applies to credentials. A directly
     * trusted leaf certificate is accepted within its validity period. Any other chain needs a PKIX
     * path to one of the trust anchors, which may be intermediate CAs. Returns null when the
     * provider has no X.509 trust, like the upstream default.
     */
    @Override
    default JWK validateX509Chain(TrustMaterialRequest request, List<String> x5c, String algorithm)
            throws VerificationException {
        List<X509Certificate> direct = directIssuerCertificates();
        List<IssuerTrustAnchors> anchors = issuerTrustAnchors();
        if (direct.isEmpty() && anchors.isEmpty()) {
            return null;
        }
        List<X509Certificate> chain = X509CertificateChainValidator.decodeCertificateChain(x5c);
        X509Certificate leaf = chain.get(0);
        if (direct.contains(leaf)) {
            try {
                leaf.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new VerificationException("The directly trusted certificate is not currently valid", e);
            }
            return X509CertificateChainValidator.toJwk(leaf, algorithm, chain);
        }
        VerificationException firstFailure = null;
        for (IssuerTrustAnchors material : anchors) {
            try {
                return X509CertificateChainValidator.validate(
                        x5c, algorithm, material.trustAnchors(), material.requiredExtendedKeyUsages());
            } catch (VerificationException e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        throw firstFailure != null
                ? firstFailure
                : new VerificationException("The x5c chain leads to none of the trusted certificates");
    }
}
