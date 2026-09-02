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
package de.arbeitsagentur.keycloak.oid4vp.conformance.runner;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;

public record ModuleRun(JsonNode created, JsonNode info) {

    /**
     * Returns the authorization endpoint of the module's wallet. The suite exports it in the module
     * info, and without that export it is derived from the module URL.
     */
    public URI authorizationEndpoint() {
        String exported = info.path("exported").path("authorization_endpoint").asText("");
        if (!exported.isBlank()) {
            return URI.create(exported);
        }
        String url = created.path("url").asText(created.path("testUrl").asText(""));
        if (url.isBlank()) {
            throw new IllegalStateException("Conformance module exposes no authorization endpoint. Creation response: "
                    + created + ", module info: " + info);
        }
        return URI.create(url.contains("/authorize") ? url : url.replaceAll("/$", "") + "/authorize");
    }
}
