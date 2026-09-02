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

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * What one credential of a presentation contributes to a reference credential binding. The credential
 * type is part of it, because the same claims out of another credential are a different statement, and
 * the claims are ordered by key so that the digest over them does not depend on the order a wallet
 * answered in or the order a provider selected them in.
 */
public record BoundCredential(String credentialType, Map<String, Object> claims) {

    public BoundCredential {
        claims = claims != null ? Collections.unmodifiableMap(new TreeMap<>(claims)) : Map.of();
    }

    public boolean isEmpty() {
        return claims.isEmpty();
    }
}
