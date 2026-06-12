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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class Oid4vpMapperConfigPropertiesTest {

    @Test
    void credentialFormat_hasCorrectConfig() {
        ProviderConfigProperty prop = Oid4vpMapperConfigProperties.credentialFormat();

        assertThat(prop.getName()).isEqualTo("credential.format");
        assertThat(prop.getType()).isEqualTo(ProviderConfigProperty.LIST_TYPE);
        assertThat(prop.getDefaultValue()).isEqualTo("dc+sd-jwt");
        assertThat(prop.getOptions()).containsExactly("dc+sd-jwt", "mso_mdoc");
    }

    @Test
    void credentialType_hasCorrectConfig() {
        ProviderConfigProperty prop = Oid4vpMapperConfigProperties.credentialType();

        assertThat(prop.getName()).isEqualTo("credential.type");
        assertThat(prop.getType()).isEqualTo(ProviderConfigProperty.STRING_TYPE);
    }

    @Test
    void claimPath_hasCorrectConfig() {
        ProviderConfigProperty prop = Oid4vpMapperConfigProperties.claimPath();

        assertThat(prop.getName()).isEqualTo("claim");
        assertThat(prop.getType()).isEqualTo(ProviderConfigProperty.STRING_TYPE);
    }

    @Test
    void claimPath_customHelpText() {
        ProviderConfigProperty prop = Oid4vpMapperConfigProperties.claimPath("Custom help");

        assertThat(prop.getHelpText()).isEqualTo("Custom help");
    }

    @Test
    void optional_hasCorrectConfig() {
        ProviderConfigProperty prop = Oid4vpMapperConfigProperties.optional();

        assertThat(prop.getName()).isEqualTo("optional");
        assertThat(prop.getType()).isEqualTo(ProviderConfigProperty.BOOLEAN_TYPE);
        assertThat(prop.getDefaultValue()).isEqualTo("false");
    }

    @Test
    void addCommonProperties_addsFiveProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();

        Oid4vpMapperConfigProperties.addCommonProperties(properties);

        assertThat(properties).hasSize(5);
        assertThat(properties.stream().map(ProviderConfigProperty::getName))
                .containsExactly("credential.format", "credential.type", "claim", "multivalued", "optional");
    }
}
