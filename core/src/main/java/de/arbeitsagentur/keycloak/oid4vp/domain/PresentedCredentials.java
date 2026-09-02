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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The credentials of a verified presentation, keyed by the DCQL credential id the wallet answered
 * under. The order is the query order.
 *
 * <p>A mapper resolves its claim path inside its own credential, because credentials of one
 * presentation share claim names and a merged view would import a value from the wrong credential.
 *
 * <p>The map is wrapped in a record because {@code SerializedBrokeredIdentityContext} restores
 * every context data value through the concrete class it recorded, and a bare {@code Map} would
 * lose its element type and come back untyped.
 */
public record PresentedCredentials(Map<String, PresentedCredential> byCredentialId) {

    public PresentedCredentials {
        byCredentialId =
                byCredentialId != null ? Collections.unmodifiableMap(new LinkedHashMap<>(byCredentialId)) : Map.of();
    }

    public static PresentedCredentials of(Map<String, VerifiedCredential> verifiedCredentials) {
        Map<String, PresentedCredential> credentials = new LinkedHashMap<>();
        verifiedCredentials.forEach((credentialId, credential) -> credentials.put(
                credentialId,
                new PresentedCredential(
                        credential.presentationType().dcqlFormat(), credential.credentialType(), credential.claims())));
        return new PresentedCredentials(credentials);
    }

    public PresentedCredential get(String credentialId) {
        return byCredentialId.get(credentialId);
    }

    public PresentedCredential firstOfFormat(String format) {
        return byCredentialId.values().stream()
                .filter(credential -> format.equals(credential.format()))
                .findFirst()
                .orElse(null);
    }
}
