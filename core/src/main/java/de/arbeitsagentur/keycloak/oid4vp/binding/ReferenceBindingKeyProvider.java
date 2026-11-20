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

import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.common.util.Base64Url;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;

/**
 * Holds the realm secret of the reference credential binding. Its own algorithm name keeps it apart from
 * the realm HMAC keys. Rotating or disabling the key that signs tokens leaves issued bindings valid.
 * Disabling this key invalidates the bindings and nothing else.
 */
public class ReferenceBindingKeyProvider implements KeyProvider {

    public static final String ALGORITHM = "OID4VP-REFERENCE-BINDING";

    static final String HMAC_ALGORITHM = "HmacSHA256";

    private final ComponentModel model;
    private final SecretKey secretKey;

    ReferenceBindingKeyProvider(ComponentModel model) {
        this.model = model;
        this.secretKey = new SecretKeySpec(Base64Url.decode(model.get(Attributes.SECRET_KEY)), HMAC_ALGORITHM);
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        KeyWrapper key = new KeyWrapper();
        key.setProviderId(model.getId());
        key.setProviderPriority(model.get(Attributes.PRIORITY_KEY, 0L));
        key.setKid(model.get(Attributes.KID_KEY));
        key.setUse(KeyUse.SIG);
        key.setType(KeyType.OCT);
        key.setAlgorithm(ALGORITHM);
        key.setStatus(KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true)));
        key.setSecretKey(secretKey);
        return Stream.of(key);
    }

    @Override
    public void close() {}
}
