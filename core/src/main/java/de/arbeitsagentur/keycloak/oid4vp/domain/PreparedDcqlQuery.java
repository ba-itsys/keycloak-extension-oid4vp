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

import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.utils.StringUtil;

/**
 * A DCQL query generated from the IdP mappers, together with the requested-claims model used to
 * validate the wallet's presentation against what was requested.
 */
public record PreparedDcqlQuery(String dcqlQuery, List<RequestedCredential> requestedCredentials) {

    public PreparedDcqlQuery {
        requestedCredentials = requestedCredentials != null ? List.copyOf(requestedCredentials) : List.of();
    }

    /** The distinct credential type identifiers of the query, used as the trusted-type allow-list. */
    public List<String> configuredCredentialTypes() {
        return requestedCredentials.stream()
                .map(RequestedCredential::type)
                .filter(StringUtil::isNotBlank)
                .collect(Collectors.collectingAndThen(Collectors.toCollection(LinkedHashSet::new), List::copyOf));
    }
}
