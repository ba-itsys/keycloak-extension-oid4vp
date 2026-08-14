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

import java.util.List;
import java.util.Map;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Factory of the trust material identity provider for credentials this Keycloak issues itself.
 * Instances are referenced by OID4VP identity providers via their {@code trustMaterialIdps}
 * setting, like every other trust material provider.
 */
public class KeycloakRealmIssuerIdentityProviderFactory
        extends AbstractIdentityProviderFactory<KeycloakRealmIssuerIdentityProvider> {

    public static final String PROVIDER_ID = "keycloak-realm-issuer";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(KeycloakRealmIssuerIdentityProviderConfig.SERVED_CREDENTIAL_TYPES)
            .label("Served Credential Types")
            .helpText("Comma separated credential types (SD-JWT VCT) this Keycloak issues. Required, so the realm "
                    + "keys are trusted for these credentials only and not for everything the verifier requests.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(KeycloakRealmIssuerIdentityProviderConfig.ISSUER_REALM)
            .label("Issuer Realm")
            .helpText("Name of the realm whose signature keys sign the credentials. "
                    + "Leave empty for the realm the OID4VP identity provider runs in.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(KeycloakRealmIssuerIdentityProviderConfig.ISSUER)
            .label("Issuer")
            .helpText("The credential 'iss' the realm keys are trusted for. Leave empty to derive it from the "
                    + "issuer realm, which is the value published by the realm's JWT VC issuer metadata.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Keycloak Realm Issuer";
    }

    @Override
    public KeycloakRealmIssuerIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new KeycloakRealmIssuerIdentityProvider(session, new KeycloakRealmIssuerIdentityProviderConfig(model));
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String config) {
        throw new UnsupportedOperationException();
    }

    @Override
    public KeycloakRealmIssuerIdentityProviderConfig createConfig() {
        return new KeycloakRealmIssuerIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
