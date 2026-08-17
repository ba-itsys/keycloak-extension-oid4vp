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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.IdentityBrokerService;

/**
 * Resolves trust material identity providers by alias into a {@link CredentialTrustPlan} for the
 * OID4VP verifier.
 *
 * <p>Counterpart of the upstream {@code TrustMaterialResolver}: providers are looked up by alias
 * from the realm, disabled or missing providers are skipped. Providers that only implement the
 * upstream {@code TrustMaterialIdentityProvider} contract (for example Keycloak's
 * {@code default-trust}) are adapted to the extension contract at lookup time, so the plan works
 * uniformly on {@link Oid4vpTrustMaterialIdentityProvider}.
 */
public class Oid4vpTrustMaterialResolver {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustMaterialResolver.class);

    /** Provider lookup indirection, replaceable in tests with a typed double. */
    public interface ProviderLookup {
        Oid4vpTrustMaterialIdentityProvider<?> byAlias(KeycloakSession session, String alias);
    }

    private final ProviderLookup providerLookup;

    public Oid4vpTrustMaterialResolver() {
        this(Oid4vpTrustMaterialResolver::lookupByAlias);
    }

    public Oid4vpTrustMaterialResolver(ProviderLookup providerLookup) {
        this.providerLookup = providerLookup;
    }

    /**
     * Resolves the trust material identity providers referenced by the comma separated alias list
     * into a plan that answers per credential type. Unknown or disabled aliases are skipped with a
     * warning, but a non-blank alias list always declares a trust source: when none of the aliases
     * resolve, the plan rejects every credential instead of falling back to issuer-published
     * metadata.
     */
    public CredentialTrustPlan resolvePlan(KeycloakSession session, String aliases) {
        List<String> configuredAliases = splitAliases(aliases);
        List<Oid4vpTrustMaterialIdentityProvider<?>> providers = resolveProviders(session, configuredAliases);
        if (!configuredAliases.isEmpty() && providers.isEmpty()) {
            LOG.errorf(
                    "None of the configured trust material identity providers %s could be resolved;"
                            + " every credential verification is rejected",
                    configuredAliases);
        }
        return new CredentialTrustPlan(providers, !configuredAliases.isEmpty());
    }

    private List<Oid4vpTrustMaterialIdentityProvider<?>> resolveProviders(
            KeycloakSession session, List<String> aliases) {
        List<Oid4vpTrustMaterialIdentityProvider<?>> providers = new ArrayList<>();
        for (String alias : aliases) {
            Oid4vpTrustMaterialIdentityProvider<?> provider = providerLookup.byAlias(session, alias);
            if (provider == null) {
                LOG.warnf(
                        "Trust material identity provider '%s' is missing, disabled or not a trust material provider; skipping",
                        alias);
                continue;
            }
            providers.add(provider);
        }
        return providers;
    }

    private static List<String> splitAliases(String aliases) {
        if (aliases == null || aliases.isBlank()) {
            return List.of();
        }
        return Arrays.stream(aliases.split(","))
                .map(String::trim)
                .filter(alias -> !alias.isEmpty())
                .toList();
    }

    private static Oid4vpTrustMaterialIdentityProvider<?> lookupByAlias(KeycloakSession session, String alias) {
        IdentityProviderModel model = session.identityProviders().getByAlias(alias);
        if (model == null || !model.isEnabled()) {
            return null;
        }
        Oid4vpTrustMaterialIdentityProvider<?> extensionProvider =
                IdentityBrokerService.getIdentityProvider(session, model, Oid4vpTrustMaterialIdentityProvider.class);
        if (extensionProvider != null) {
            return extensionProvider;
        }
        TrustMaterialIdentityProvider<?> upstreamProvider =
                IdentityBrokerService.getIdentityProvider(session, model, TrustMaterialIdentityProvider.class);
        return upstreamProvider != null ? new UpstreamTrustMaterialAdapter(upstreamProvider) : null;
    }

    /**
     * Adapts a provider that only implements the upstream contract, for example Keycloak's
     * {@code default-trust}, which publishes the JWKs of an issuer that has no trust list. Its keys
     * are consumed and trusted for any issuer, because the upstream contract does not bind them to
     * one. The credential types it serves are read from its configuration, so such a provider can be
     * scoped like the providers of this extension.
     */
    record UpstreamTrustMaterialAdapter(TrustMaterialIdentityProvider<?> delegate)
            implements Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> {

        @Override
        public List<String> servedCredentialTypes() {
            return ServedCredentialTypes.of(delegate.getConfig());
        }

        @Override
        public IdentityProviderModel getConfig() {
            return delegate.getConfig();
        }

        @Override
        public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
            return delegate.resolveKeys(request);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
