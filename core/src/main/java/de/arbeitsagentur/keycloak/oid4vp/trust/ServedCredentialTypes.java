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
 * for, stored as a comma separated value in the configuration of that provider. An empty value
 * serves every credential type.
 *
 * <p>The setting lives on the configured provider instance rather than on the Java contract it
 * implements, so a provider this extension does not own can be scoped as well. Keycloak's
 * {@code default-trust}, the provider for an issuer that publishes plain JWKs instead of a trust
 * list, would otherwise be trusted for every credential of every request that references it.
 */
public final class ServedCredentialTypes {

    public static final String CONFIG_KEY = "servedCredentialTypes";

    private ServedCredentialTypes() {}

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
