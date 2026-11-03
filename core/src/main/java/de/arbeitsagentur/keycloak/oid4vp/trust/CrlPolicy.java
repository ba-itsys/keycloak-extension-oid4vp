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

import java.time.Duration;

/**
 * Describes how one trust material identity provider checks the issuer certificates it vouches for
 * against their CRLs. Providers stay isolated: each downloads and caches CRLs itself, even when they
 * share a CA, and the settings of one never apply to a credential another vouches for. A non-null
 * {@code endpoint} replaces the distribution points of the certificate that signed the credential.
 * With {@code required}, a credential is rejected when a CRL check cannot produce a CRL.
 */
public record CrlPolicy(String providerId, String endpoint, Duration maxCacheTtl, boolean required) {

    public static final int DEFAULT_MAX_CACHE_TTL_SECONDS = 3600;
    public static final CrlPolicy DEFAULT =
            new CrlPolicy(null, null, Duration.ofSeconds(DEFAULT_MAX_CACHE_TTL_SECONDS), false);
}
