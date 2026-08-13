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

class EtsiTrustListIdentityProviderFactoryTest {

    private final EtsiTrustListIdentityProviderFactory factory = new EtsiTrustListIdentityProviderFactory();

    @Test
    void identifiesItselfAsEtsiTrustList() {
        assertThat(factory.getId()).isEqualTo("etsi-trust-list");
        assertThat(factory.getName()).isEqualTo("ETSI Trust List");
    }

    @Test
    void createsProviderFromModel() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.getConfig().put(EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL, "https://tl.example/list.jwt");

        EtsiTrustListIdentityProvider provider = factory.create(null, model);

        assertThat(provider.getConfig().getTrustListUrl()).isEqualTo("https://tl.example/list.jwt");
        assertThat(provider.trustListUrl()).contains("https://tl.example/list.jwt");
        provider.close();
    }

    @Test
    void createConfigIsHiddenFromLogin() {
        EtsiTrustListIdentityProviderConfig config = factory.createConfig();
        assertThat(config.isHideOnLogin()).isTrue();
    }

    @Test
    void parseConfigIsUnsupported() {
        assertThatThrownBy(() -> factory.parseConfig(null, "{}")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void exposesTrustListAndStaticCertificateProperties() {
        List<String> propertyNames = factory.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .toList();

        assertThat(propertyNames)
                .containsExactly(
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL,
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM,
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_LOTE_TYPE,
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_CACHE_TTL_SECONDS,
                        EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_STALE_AGE_SECONDS,
                        EtsiTrustListIdentityProviderConfig.TRUSTED_CERTIFICATES,
                        EtsiTrustListIdentityProviderConfig.REQUIRED_EXTENDED_KEY_USAGES);
    }
}
