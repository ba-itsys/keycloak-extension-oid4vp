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
package de.arbeitsagentur.keycloak.oid4vp.authentication;

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.util.Objects;

/**
 * A verified OID4VP presentation that an authenticator or required action asked for.
 *
 * @param identityKey the identity key a login through the identity provider links, null when the
 *     presentation identifies nobody
 * @param subjectCredentialMissing whether the presentation lacked the subject credential that
 *     {@code allowMissingSubjectCredential} lets a wallet leave out
 */
public record Oid4vpPresentation(
        String identityProviderAlias,
        String execution,
        String identityKey,
        boolean subjectCredentialMissing,
        PresentedCredentials credentials,
        String issuer,
        String presentationFlow) {

    public Oid4vpPresentation {
        Objects.requireNonNull(identityProviderAlias, "identityProviderAlias");
        Objects.requireNonNull(execution, "execution");
        Objects.requireNonNull(credentials, "credentials");
    }
}
