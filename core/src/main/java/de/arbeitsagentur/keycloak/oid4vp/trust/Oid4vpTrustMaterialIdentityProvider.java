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
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trust material identity provider contract of this extension, extending the upstream JWK and X.509
 * surfaces with revocation (status list) trust, directly trusted issuer certificates for pinned or
 * chainless credentials, the credential types the provider serves, and the DCQL
 * {@code trusted_authorities} entries it can advertise. Every method defaults to empty, so a
 * provider implements only the surfaces it serves, as upstream does.
 */
public interface Oid4vpTrustMaterialIdentityProvider<C extends IdentityProviderModel>
        extends X509TrustMaterialIdentityProvider<C> {

    /**
     * Returns the end entity certificates listed as issuance services. Their keys are trusted
     * directly for credentials that carry no certificate chain, and a presented chain whose leaf
     * equals one of these certificates is trusted without further path building.
     */
    default List<X509Certificate> directIssuerCertificates() {
        return List.of();
    }

    default List<X509Certificate> revocationCertificates() {
        return List.of();
    }

    /**
     * Returns the credential types (SD-JWT VCT, mDoc doctype) this provider is trusted for. An empty
     * list serves every credential type.
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
     * publish keys instead of X.509 anchors implement this instead of {@link #resolveX509Trust}.
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
     * {@link #directIssuerCertificates()}, whose certificates carry no issuer because a trust list
     * names services rather than credential issuers. A provider that knows the issuer of its
     * certificates overrides this, and those certificates then cannot verify a credential claiming
     * to come from somewhere else.
     */
    default List<TrustedIssuerCertificate> trustedIssuerCertificates() {
        return directIssuerCertificates().stream()
                .map(TrustedIssuerCertificate::ofAnyIssuer)
                .toList();
    }
}
