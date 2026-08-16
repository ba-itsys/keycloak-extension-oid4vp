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

import java.util.Arrays;
import java.util.List;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.utils.StringUtil;

/**
 * The credential types (SD-JWT VCT, mDoc doctype) a trust material identity provider is trusted
 * for, stored as a comma separated value in the configuration of that provider.
 *
 * <p>The setting belongs to the configured provider instance rather than to the Java contract it
 * implements, so a provider this extension does not own can be scoped as well. Keycloak's
 * {@code default-trust} is the one an OID4VP deployment reaches for when an issuer publishes plain
 * JWKs instead of a trust list, and without this it would be trusted for every credential of every
 * request that references it.
 *
 * <p>An empty value serves every credential type.
 */
public final class ServedCredentialTypes {

    public static final String CONFIG_KEY = "servedCredentialTypes";

    private ServedCredentialTypes() {}

    /** The credential types the given provider configuration declares. */
    public static List<String> of(IdentityProviderModel model) {
        return model == null ? List.of() : parse(model.getConfig().get(CONFIG_KEY));
    }

    private static List<String> parse(String commaSeparatedCredentialTypes) {
        if (StringUtil.isBlank(commaSeparatedCredentialTypes)) {
            return List.of();
        }
        return Arrays.stream(commaSeparatedCredentialTypes.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .distinct()
                .toList();
    }
}
