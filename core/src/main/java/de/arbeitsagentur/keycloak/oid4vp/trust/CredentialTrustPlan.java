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
 * credential type.
 *
 * <p>A provider serves the credential types it declares. A provider that declares none serves every
 * type, which is what an unscoped configuration means. Credentials of different types therefore see
 * different trust material, so a credential from a trusted list is not accepted under the anchors of
 * an unrelated trust domain, and the other way around.
 *
 * <p>Resolution per type is memoised, because both the request side (one DCQL entry per credential)
 * and the response side (one presented credential per entry) ask repeatedly within a single flow.
 */
public class CredentialTrustPlan {

    /**
     * Memo key of the trust serving no particular credential type, which only the providers that
     * serve every type contribute to. A map key cannot be null, and no credential type is empty.
     */
    private static final String UNSCOPED = "";

    private final List<Oid4vpTrustMaterialIdentityProvider<?>> providers;
    private final Map<String, ResolvedTrust> resolvedByCredentialType = new ConcurrentHashMap<>();

    public CredentialTrustPlan(List<Oid4vpTrustMaterialIdentityProvider<?>> providers) {
        this.providers = List.copyOf(providers);
    }

    public static CredentialTrustPlan empty() {
        return new CredentialTrustPlan(List.of());
    }

    /** Whether any provider was resolved at all. */
    public boolean hasProviders() {
        return !providers.isEmpty();
    }

    /**
     * Whether at least one provider restricts itself to certain credential types. While no provider
     * does, every credential sees the same material and a type without a dedicated provider is not
     * a configuration problem.
     */
    public boolean isScopedByCredentialType() {
        return providers.stream()
                .anyMatch(provider -> !provider.servedCredentialTypes().isEmpty());
    }

    /**
     * The trust material serving the given credential type. Resolved on first use, because pulling
     * trust material can involve a trust list fetch that must not run while a login page is only
     * being rendered.
     */
    public ResolvedTrust forCredentialType(String credentialType) {
        String key = StringUtil.isBlank(credentialType) ? UNSCOPED : credentialType;
        return resolvedByCredentialType.computeIfAbsent(key, this::resolve);
    }

    /**
     * The DCQL {@code trusted_authorities} entries the providers serving this credential type
     * advertise. Only the advertisement is pulled, never the trust anchors, so building the
     * authorization request stays independent of whether the trust material is currently reachable.
     */
    public List<TrustedAuthority> trustedAuthoritiesFor(String credentialType) {
        List<TrustedAuthority> trustedAuthorities = new ArrayList<>();
        for (Oid4vpTrustMaterialIdentityProvider<?> provider : providers) {
            if (serves(provider, credentialType)) {
                trustedAuthorities.addAll(provider.trustedAuthorities());
            }
        }
        return TrustedAuthority.merge(trustedAuthorities);
    }

    /** Whether any provider serves the given credential type. */
    public boolean serves(String credentialType) {
        return providers.stream().anyMatch(provider -> serves(provider, credentialType));
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
                TrustedAuthority.merge(trustedAuthorities));
    }

    /** A provider without declared credential types serves all of them. */
    private static boolean serves(Oid4vpTrustMaterialIdentityProvider<?> provider, String credentialType) {
        List<String> servedCredentialTypes = provider.servedCredentialTypes();
        return servedCredentialTypes.isEmpty()
                || (credentialType != null && servedCredentialTypes.contains(credentialType));
    }
}
