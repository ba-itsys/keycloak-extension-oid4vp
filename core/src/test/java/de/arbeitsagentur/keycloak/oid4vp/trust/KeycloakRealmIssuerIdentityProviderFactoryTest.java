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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.provider.ProviderConfigProperty;

class KeycloakRealmIssuerIdentityProviderFactoryTest {

    private final KeycloakRealmIssuerIdentityProviderFactory factory = new KeycloakRealmIssuerIdentityProviderFactory();

    @Test
    void identifiesItselfAsKeycloakRealmIssuer() {
        assertThat(factory.getId()).isEqualTo("keycloak-realm-issuer");
        assertThat(factory.getName()).isEqualTo("Keycloak Realm Issuer");
    }

    @Test
    void createsProviderFromModel() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.getConfig()
                .put(
                        KeycloakRealmIssuerIdentityProviderConfig.SERVED_CREDENTIAL_TYPES,
                        "https://kc.example/badge, https://kc.example/membership");
        model.getConfig().put(KeycloakRealmIssuerIdentityProviderConfig.ISSUER_REALM, "company");
        model.getConfig().put(KeycloakRealmIssuerIdentityProviderConfig.ISSUER, "https://kc.example/realms/company");

        KeycloakRealmIssuerIdentityProvider provider = factory.create(null, model);

        assertThat(provider.servedCredentialTypes())
                .containsExactly("https://kc.example/badge", "https://kc.example/membership");
        assertThat(provider.getConfig().getIssuerRealm()).isEqualTo("company");
        assertThat(provider.getConfig().getIssuer()).isEqualTo("https://kc.example/realms/company");
        assertThat(provider.trustedAuthorities())
                .as("realm keys are no authority a wallet could match against")
                .isEmpty();
        provider.close();
    }

    @Test
    void createConfigIsHiddenFromLoginAndWritable() {
        KeycloakRealmIssuerIdentityProviderConfig config = factory.createConfig();

        assertThat(config.isHideOnLogin()).isTrue();

        config.setIssuerRealm("company");
        config.setIssuer("https://kc.example/realms/company");
        config.setServedCredentialTypes("https://kc.example/badge");
        assertThat(config.getIssuerRealm()).isEqualTo("company");
        assertThat(config.getIssuer()).isEqualTo("https://kc.example/realms/company");
        assertThat(config.getServedCredentialTypes()).containsExactly("https://kc.example/badge");
    }

    @Test
    void parseConfigIsUnsupported() {
        assertThatThrownBy(() -> factory.parseConfig(null, "{}")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void exposesTheRealmIssuerProperties() {
        List<String> propertyNames = factory.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .toList();

        assertThat(propertyNames)
                .containsExactly(
                        KeycloakRealmIssuerIdentityProviderConfig.SERVED_CREDENTIAL_TYPES,
                        KeycloakRealmIssuerIdentityProviderConfig.ISSUER_REALM,
                        KeycloakRealmIssuerIdentityProviderConfig.ISSUER);
    }
}
