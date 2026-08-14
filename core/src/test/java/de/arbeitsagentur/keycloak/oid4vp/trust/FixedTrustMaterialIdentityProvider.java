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
import java.util.stream.Stream;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trust material identity provider double that serves fixed material for the credential types it
 * declares, so tests can compose trust domains the way an admin composes provider instances.
 */
public class FixedTrustMaterialIdentityProvider implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

    private final ResolvedTrust trust;
    private final List<String> servedCredentialTypes;

    public FixedTrustMaterialIdentityProvider(ResolvedTrust trust, List<String> servedCredentialTypes) {
        this.trust = trust;
        this.servedCredentialTypes = List.copyOf(servedCredentialTypes);
    }

    public static FixedTrustMaterialIdentityProvider serving(ResolvedTrust trust, String... credentialTypes) {
        return new FixedTrustMaterialIdentityProvider(trust, List.of(credentialTypes));
    }

    @Override
    public IdentityProviderModel getConfig() {
        return new IdentityProviderModel();
    }

    @Override
    public List<String> servedCredentialTypes() {
        return servedCredentialTypes;
    }

    @Override
    public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
        return trust.trustedIssuerKeys().stream().map(TrustedIssuerKey::jwk);
    }

    @Override
    public List<TrustedIssuerKey> trustedIssuerKeys() {
        return trust.trustedIssuerKeys();
    }

    @Override
    public Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
        return trust.issuanceTrust().stream();
    }

    @Override
    public List<X509Certificate> directIssuerCertificates() {
        return trust.directIssuerCertificates();
    }

    @Override
    public List<X509Certificate> revocationCertificates() {
        return trust.revocationCertificates();
    }

    @Override
    public List<TrustedAuthority> trustedAuthorities() {
        return trust.trustedAuthorities();
    }

    @Override
    public void close() {}
}
