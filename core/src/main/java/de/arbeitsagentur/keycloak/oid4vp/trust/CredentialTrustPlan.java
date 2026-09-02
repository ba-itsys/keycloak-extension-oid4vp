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
import org.keycloak.broker.provider.TrustMaterialRequest;
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
     * Memo key for the trust that serves no particular credential type, contributed to only by the
     * providers that serve every type. It is the empty string because a map key cannot be null and
     * no credential type is empty.
     */
    private static final String UNSCOPED = "";

    private final List<Oid4vpTrustMaterialIdentityProvider<?>> providers;
    private final boolean trustDeclared;
    private final Map<String, ResolvedTrust> resolvedByCredentialType = new ConcurrentHashMap<>();

    public CredentialTrustPlan(List<Oid4vpTrustMaterialIdentityProvider<?>> providers) {
        this(providers, !providers.isEmpty());
    }

    /**
     * @param trustDeclared whether the configuration names any trust source. This stays true when
     *     none of the named providers can be resolved. A broken configuration then rejects
     *     credentials instead of re-enabling the issuer metadata fallback.
     */
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

    /**
     * Returns the trust material serving the given credential type, see {@link #servingType}.
     * Resolution happens on first use, because pulling trust material can involve a trust list
     * fetch and that fetch must not run while a login page is only being rendered.
     */
    public ResolvedTrust forCredentialType(String credentialType) {
        if (StringUtil.isBlank(credentialType)) {
            return resolvedByCredentialType.computeIfAbsent(UNSCOPED, this::resolve);
        }
        return forServingType(servingType(credentialType, List.of()));
    }

    /** Returns the trust material for a presented credential, chosen by {@link #servingType}. */
    public ResolvedTrust forCredential(ClaimedTypes claimed) {
        return forServingType(servingType(claimed.type(), claimed.alsoKnownAs()));
    }

    private ResolvedTrust forServingType(String servingType) {
        return resolvedByCredentialType.computeIfAbsent(servingType, this::resolve);
    }

    /**
     * Returns the DCQL {@code trusted_authorities} entries the providers serving this credential
     * type advertise. Only the advertisement is pulled, never the trust anchors, so building the
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

    /** Returns whether any provider serves the given credential type or a type it derives from. */
    public boolean serves(String credentialType) {
        String servingType = servingType(credentialType, List.of());
        return providers.stream().anyMatch(provider -> serves(provider, servingType));
    }

    /**
     * Returns the type whose providers judge a credential. It walks the types the credential is of,
     * nearest first, and takes the first one a provider declares, so a provider for the derived type
     * wins over one for the base type while a base type's provider still covers derived types that
     * have none of their own. Falling back to the type itself leaves the credential to the unscoped
     * providers.
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
        TrustMaterialRequest request = TrustMaterialRequest.builder().build();
        List<X509TrustMaterial> issuanceTrust = new ArrayList<>();
        List<TrustedIssuerKey> trustedIssuerKeys = new ArrayList<>();
        List<TrustedAuthority> trustedAuthorities = new ArrayList<>();
        Set<TrustedIssuerCertificate> directIssuerCertificates = new LinkedHashSet<>();
        Set<X509Certificate> revocationCertificates = new LinkedHashSet<>();

        for (Oid4vpTrustMaterialIdentityProvider<?> provider : providers) {
            if (!serves(provider, credentialType)) {
                continue;
            }
            issuanceTrust.addAll(provider.resolveX509Trust(request).toList());
            trustedIssuerKeys.addAll(provider.trustedIssuerKeys());
            directIssuerCertificates.addAll(provider.trustedIssuerCertificates());
            revocationCertificates.addAll(provider.revocationCertificates());
            trustedAuthorities.addAll(provider.trustedAuthorities());
        }

        return new ResolvedTrust(
                issuanceTrust,
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
