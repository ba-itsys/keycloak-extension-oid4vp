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
package de.arbeitsagentur.keycloak.oid4vp.authentication;

import java.util.List;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class Oid4vpPresentationAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "oid4vp-presentation";
    public static final String IDENTITY_PROVIDER = "identityProvider";

    private static final Oid4vpPresentationAuthenticator INSTANCE = new Oid4vpPresentationAuthenticator();

    static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(IDENTITY_PROVIDER)
            .label("OID4VP identity provider")
            .helpText("Alias of the OID4VP identity provider whose mappers define the requested credentials and "
                    + "whose verifier settings and trust material verify the presentation.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .build();

    static String identityProviderAlias(Map<String, String> config) {
        String alias = config.get(IDENTITY_PROVIDER);
        if (alias == null || alias.isBlank()) {
            throw new IllegalStateException(
                    "The OID4VP presentation names no identity provider. Configure '" + IDENTITY_PROVIDER + "'");
        }
        return alias.strip();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "OID4VP presentation";
    }

    @Override
    public String getReferenceCategory() {
        return "oid4vp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Identifies the user by an OID4VP presentation linked through an OID4VP identity provider. Works as a "
                + "passwordless login or as a second factor.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
