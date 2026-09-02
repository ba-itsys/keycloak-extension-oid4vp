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
 * A DCQL query generated from the identity provider mappers. It carries the requested credentials
 * and credential sets along, because the wallet's presentation is validated against them.
 */
public record PreparedDcqlQuery(
        String dcqlQuery, List<RequestedCredential> requestedCredentials, List<CredentialSet> credentialSets) {

    public PreparedDcqlQuery {
        requestedCredentials = requestedCredentials != null ? List.copyOf(requestedCredentials) : List.of();
        credentialSets = credentialSets != null ? List.copyOf(credentialSets) : List.of();
    }
}
