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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * One credential of a verified presentation, as the identity provider mappers see it.
 *
 * @param format the DCQL credential format
 * @param type the credential type identifier: the VCT for SD-JWT, the doctype for mDoc
 * @param claims the claims of this credential alone; mDoc claims stay nested under their namespace
 */
public record PresentedCredential(String format, String type, Map<String, Object> claims) {

    public PresentedCredential {
        claims = claims != null ? Collections.unmodifiableMap(new LinkedHashMap<>(claims)) : Map.of();
    }

    /** The claims as a JSON tree, which is what a {@code ClaimPath} resolves against. */
    public JsonNode claimsNode() {
        return JsonSerialization.mapper.valueToTree(claims);
    }
}
