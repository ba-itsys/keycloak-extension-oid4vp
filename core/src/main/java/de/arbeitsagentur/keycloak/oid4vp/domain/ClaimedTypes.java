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

import java.util.List;

/**
 * The credential types a presentation claims, read from the token before any signature is checked:
 * the {@code vct} of an SD-JWT VC together with its {@code aka_vcts} entries, or the
 * {@code docType} of an mDoc.
 *
 * <p>These values are unverified, so they never grant anything. They only select which of the
 * requested types the presentation is judged against, and which trust material applies to it.
 */
public record ClaimedTypes(String type, List<String> alsoKnownAs) {

    public ClaimedTypes {
        alsoKnownAs = alsoKnownAs != null ? List.copyOf(alsoKnownAs) : List.of();
    }

    public boolean isOfType(String requestedType) {
        return CredentialTypeHierarchy.isOfType(type, alsoKnownAs, requestedType);
    }
}
