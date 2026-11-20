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

import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.AbstractGeneratedSecretKeyProviderFactory;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.SecretKeyProviderUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

// Creates the key on first use, so a realm needs no setup and an existing realm gets its own binding key.
public class ReferenceBindingKeyProviderFactory
        extends AbstractGeneratedSecretKeyProviderFactory<ReferenceBindingKeyProvider> {

    public static final String PROVIDER_ID = "oid4vp-reference-binding-generated";

    private static final Logger LOG = Logger.getLogger(ReferenceBindingKeyProviderFactory.class);

    private static final int DEFAULT_KEY_SIZE = 32;

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = SecretKeyProviderUtils.configurationBuilder()
            .property(Attributes.SECRET_SIZE_PROPERTY)
            .build();

    @Override
    public ReferenceBindingKeyProvider create(KeycloakSession session, ComponentModel model) {
        return new ReferenceBindingKeyProvider(model);
    }

    @Override
    public boolean createFallbackKeys(KeycloakSession session, KeyUse keyUse, String algorithm) {
        if (!KeyUse.SIG.equals(keyUse) || !ReferenceBindingKeyProvider.ALGORITHM.equals(algorithm)) {
            return false;
        }
        RealmModel realm = session.getContext().getRealm();
        ComponentModel generated = new ComponentModel();
        generated.setName("fallback-" + algorithm);
        generated.setParentId(realm.getId());
        generated.setProviderId(PROVIDER_ID);
        generated.setProviderType(KeyProvider.class.getName());
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Attributes.PRIORITY_KEY, "-100");
        generated.setConfig(config);
        realm.addComponentModel(generated);
        return true;
    }

    @Override
    public String getHelpText() {
        return "Generates the secret of the OID4VP reference credential binding";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected Logger logger() {
        return LOG;
    }

    @Override
    protected int getDefaultKeySize() {
        return DEFAULT_KEY_SIZE;
    }
}
