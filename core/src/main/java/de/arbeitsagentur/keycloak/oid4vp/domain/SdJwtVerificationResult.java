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
import java.util.Map;

/**
 * The result of verifying an SD-JWT VC from a {@code vp_token}. The claims are the disclosed ones
 * after selective disclosure resolution, the credential type is the VCT, and
 * {@code alsoKnownAsTypes} are the further types the {@code aka_vcts} claim names.
 */
public record SdJwtVerificationResult(
        Map<String, Object> claims, String issuer, String credentialType, List<String> alsoKnownAsTypes) {

    public SdJwtVerificationResult {
        alsoKnownAsTypes = alsoKnownAsTypes != null ? List.copyOf(alsoKnownAsTypes) : List.of();
    }

    public SdJwtVerificationResult(Map<String, Object> claims, String issuer, String credentialType) {
        this(claims, issuer, credentialType, List.of());
    }
}
