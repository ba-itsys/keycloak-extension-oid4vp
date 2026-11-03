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

import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimedTypes;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeHierarchy;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.utils.StringUtil;

/**
 * The trust material identity providers configured on an OID4VP identity provider, resolved per
 * credential type. A provider serves the credential types it declares, and one that declares none
 * serves every type, so credentials of different types can see different trust material. A
 * credential from one trust domain is never accepted under the anchors of an unrelated trust
 * domain.
 */
public class CredentialTrustPlan {

    /**
     * Memo key for the trust that serves no particular credential type, which only the providers
     * serving every type contribute to. It is the empty string because a map key cannot be null and
     * no credential type is empty.
     */
    private static final String UNSCOPED = "";

    private final List<Oid4vpTrustMaterialIdentityProvider<?>> providers;
    private final boolean trustDeclared;
    private final Map<String, ResolvedTrust> resolvedByCredentialType = new ConcurrentHashMap<>();

    public CredentialTrustPlan(List<Oid4vpTrustMaterialIdentityProvider<?>> providers) {
        this(providers, !providers.isEmpty());
    }

    public CredentialTrustPlan(List<Oid4vpTrustMaterialIdentityProvider<?>> providers, boolean trustDeclared) {
        this.providers = List.copyOf(providers);
        this.trustDeclared = trustDeclared;
    }

    public static CredentialTrustPlan empty() {
        return new CredentialTrustPlan(List.of());
    }

    public boolean hasProviders() {
        return !providers.isEmpty();
    }

    public boolean isScopedByCredentialType() {
        return providers.stream()
                .anyMatch(provider -> !provider.servedCredentialTypes().isEmpty());
    }

    // Resolves on first use, because resolving can fetch a trust list and rendering the login page must not.
    public ResolvedTrust forCredentialType(String credentialType) {
        if (StringUtil.isBlank(credentialType)) {
            return resolvedByCredentialType.computeIfAbsent(UNSCOPED, this::resolve);
        }
        return forServingType(servingType(credentialType, List.of()));
    }

    public ResolvedTrust forCredential(ClaimedTypes claimed) {
        return forServingType(servingType(claimed.type(), claimed.alsoKnownAs()));
    }

    private ResolvedTrust forServingType(String servingType) {
        return resolvedByCredentialType.computeIfAbsent(servingType, this::resolve);
    }

    /**
     * Returns the DCQL {@code trusted_authorities} entries the providers serving this credential
     * type advertise. Only the advertisement is read, never the trust anchors, so building the
     * authorization request does not depend on whether the trust material is reachable.
     */
    public List<TrustedAuthority> trustedAuthoritiesFor(String credentialType) {
        String servingType = servingType(credentialType, List.of());
        List<TrustedAuthority> trustedAuthorities = new ArrayList<>();
        for (Oid4vpTrustMaterialIdentityProvider<?> provider : providers) {
            if (serves(provider, servingType)) {
                trustedAuthorities.addAll(provider.trustedAuthorities());
            }
        }
        return TrustedAuthority.merge(trustedAuthorities);
    }

    // Treats a provider for a base type as serving the derived type too.
    public boolean serves(String credentialType) {
        String servingType = servingType(credentialType, List.of());
        return providers.stream().anyMatch(provider -> serves(provider, servingType));
    }

    /**
     * Returns the type whose providers judge a credential: the first type of the credential, nearest
     * first, that a provider declares. A provider for a derived type thus takes precedence over one
     * for its base type, and a base type's provider covers derived types without a provider of their
     * own. A type named in {@code aka_vcts} applies only when no provider declares the credential's
     * own type or one of its base types. When no provider declares any of them, the unscoped providers
     * judge the credential.
     */
    public String servingType(String credentialType, List<String> alsoKnownAs) {
        return CredentialTypeHierarchy.typesOf(credentialType, alsoKnownAs).stream()
                .filter(this::declared)
                .findFirst()
                .orElse(credentialType);
    }

    private boolean declared(String credentialType) {
        return providers.stream()
                .anyMatch(provider -> provider.servedCredentialTypes().contains(credentialType));
    }

    private ResolvedTrust resolve(String credentialType) {
        List<IssuerTrustAnchors> issuerTrustAnchors = new ArrayList<>();
        List<TrustedIssuerKey> trustedIssuerKeys = new ArrayList<>();
        List<TrustedAuthority> trustedAuthorities = new ArrayList<>();
        Set<TrustedIssuerCertificate> directIssuerCertificates = new LinkedHashSet<>();
        Set<X509Certificate> revocationCertificates = new LinkedHashSet<>();

        for (Oid4vpTrustMaterialIdentityProvider<?> provider : providers) {
            if (!serves(provider, credentialType)) {
                continue;
            }
            issuerTrustAnchors.addAll(provider.issuerTrustAnchors());
            trustedIssuerKeys.addAll(provider.trustedIssuerKeys());
            directIssuerCertificates.addAll(provider.trustedIssuerCertificates());
            revocationCertificates.addAll(provider.revocationCertificates());
            trustedAuthorities.addAll(provider.trustedAuthorities());
        }

        return new ResolvedTrust(
                issuerTrustAnchors,
                List.copyOf(directIssuerCertificates),
                trustedIssuerKeys,
                List.copyOf(revocationCertificates),
                TrustedAuthority.merge(trustedAuthorities),
                // Any configured trust source means trust is declared, so a credential type that no
                // provider serves and a configuration whose providers cannot be resolved both end in
                // rejection instead of falling back to the issuer's self-published metadata.
                trustDeclared);
    }

    private static boolean serves(Oid4vpTrustMaterialIdentityProvider<?> provider, String credentialType) {
        List<String> servedCredentialTypes = provider.servedCredentialTypes();
        return servedCredentialTypes.isEmpty()
                || (credentialType != null && servedCredentialTypes.contains(credentialType));
    }
}
