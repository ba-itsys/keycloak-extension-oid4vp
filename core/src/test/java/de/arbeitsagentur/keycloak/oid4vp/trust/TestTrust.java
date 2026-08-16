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

import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds {@link ResolvedTrust} aggregates for tests the way the ETSI trust list identity provider
 * partitions its certificates: CA certificates become PKIX trust anchors, every certificate is
 * also a directly trusted issuer certificate, and the same set serves revocation checks.
 */
public final class TestTrust {

    private TestTrust() {}

    public static ResolvedTrust ofCertificates(List<X509Certificate> certificates) {
        Set<X509Certificate> anchors = new LinkedHashSet<>();
        for (X509Certificate certificate : certificates) {
            if (certificate.getBasicConstraints() >= 0) {
                anchors.add(certificate);
            }
        }
        List<X509TrustMaterial> issuanceTrust =
                anchors.isEmpty() ? List.of() : List.of(new X509TrustMaterial(anchors, List.of()));
        return new ResolvedTrust(issuanceTrust, anyIssuer(certificates), List.of(), certificates, List.of());
    }

    /** Certificates the way a trust list contributes them: trusted, but not tied to an issuer. */
    public static List<TrustedIssuerCertificate> anyIssuer(List<X509Certificate> certificates) {
        return certificates.stream().map(TrustedIssuerCertificate::ofAnyIssuer).toList();
    }

    public static ResolvedTrust ofCertificates(X509Certificate... certificates) {
        return ofCertificates(List.of(certificates));
    }

    /** Trust that identifies the issuer by key instead of by certificate, as a JWKS trust domain does. */
    public static ResolvedTrust ofIssuerKeys(TrustedIssuerKey... issuerKeys) {
        return new ResolvedTrust(List.of(), List.of(), List.of(issuerKeys), List.of(), List.of());
    }

    /** A plan with one provider serving the given credential types, or every type when none are given. */
    public static CredentialTrustPlan planOf(ResolvedTrust trust, String... servedCredentialTypes) {
        return new CredentialTrustPlan(
                List.of(FixedTrustMaterialIdentityProvider.serving(trust, servedCredentialTypes)));
    }
}
