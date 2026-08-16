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
package de.arbeitsagentur.keycloak.oid4vp.binding;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Binds an issued credential to the PID of its holder, which is the case this extension is built
 * for. A person is identified by a PID, and the credential this Keycloak issues carries the account
 * that person signs in to.
 *
 * <p>The defaults are the mandatory PID attributes of the EUDI wallet, in both formats. They
 * identify a person and change rarely. A change is not a lockout: the user signs in with a password
 * once and receives a credential bound to the PID of today.
 *
 * <p>Configured through the server configuration, because the login that issues a credential and the
 * login that presents it again have to select the same claims, and those two run in places that
 * share no other configuration.
 *
 * <pre>
 * --spi-oid4vp-reference-credential-binding-pid-credential-types=urn:eudi:pid:1
 * --spi-oid4vp-reference-credential-binding-pid-claims=given_name,family_name,birthdate
 * </pre>
 */
public class PidReferenceBindingProviderFactory implements ReferenceCredentialBindingProviderFactory {

    public static final String PROVIDER_ID = "pid";

    /** Credential types to bind to. Empty binds to every credential presented alongside. */
    public static final String CREDENTIAL_TYPES = "credential-types";

    /** Claim paths to bind to, in the dot notation the OID4VP mappers use. Required. */
    public static final String CLAIMS = "claims";

    static final String DEFAULT_CREDENTIAL_TYPES = "urn:eudi:pid:1,eu.europa.ec.eudi.pid.1";
    static final String DEFAULT_CLAIMS = "given_name,family_name,birthdate";

    private Set<String> credentialTypes = Set.copyOf(parse(DEFAULT_CREDENTIAL_TYPES));
    private List<String> claimPaths = parseClaims(DEFAULT_CLAIMS);

    @Override
    public ReferenceCredentialBindingProvider create(KeycloakSession session) {
        return new PidReferenceBindingProvider(credentialTypes, claimPaths);
    }

    @Override
    public void init(Config.Scope config) {
        credentialTypes = Set.copyOf(parse(config.get(CREDENTIAL_TYPES, DEFAULT_CREDENTIAL_TYPES)));
        claimPaths = parseClaims(config.get(CLAIMS, DEFAULT_CLAIMS));
    }

    /**
     * The claim paths to bind to. At least one is required: binding to every claim of a credential
     * would cover the issuance metadata as well, so a re-issued credential of the same person, or
     * another copy of a batch issued one, would already break the binding.
     */
    static List<String> parseClaims(String configured) {
        List<String> claimPaths = parse(configured);
        if (claimPaths.isEmpty()) {
            throw new IllegalArgumentException("The OID4VP reference credential binding provider '" + PROVIDER_ID
                    + "' needs at least one claim path in '" + CLAIMS
                    + "'. Binding to every claim of a credential breaks on the next re-issuance of it.");
        }
        return claimPaths;
    }

    /** The configured values in order, without blanks and duplicates. */
    static List<String> parse(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .distinct()
                .toList();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CREDENTIAL_TYPES)
                .label("Credential types")
                .helpText("Credential types the issued credential is bound to, as VCT or doctype. Empty binds it to "
                        + "every credential presented with it.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_CREDENTIAL_TYPES)
                .add()
                .property()
                .name(CLAIMS)
                .label("Claim paths")
                .helpText("Claim paths the issued credential is bound to, in dot notation. At least one is required. "
                        + "Prefer claims that identify a person and change rarely, because every change of one of "
                        + "them costs the user a password login.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_CLAIMS)
                .add()
                .build();
    }
}
