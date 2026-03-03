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

import java.util.Map;

/**
 * Result of verifying an SD-JWT Verifiable Credential presented in a {@code vp_token}.
 *
 * <p>Contains the disclosed claims after selective disclosure resolution, the issuer identifier,
 * and the credential type (VCT). Produced by {@link de.arbeitsagentur.keycloak.oid4vp.verification.SdJwtVerifier}.
 */
public record SdJwtVerificationResult(Map<String, Object> claims, String issuer, String credentialType) {}
