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
 * Specification of a credential type to request, used when building DCQL queries from IdP mappers.
 *
 * @param format the credential format ({@code dc+sd-jwt} or {@code mso_mdoc})
 * @param type the credential type identifier (VCT for SD-JWT, doctype for mDoc)
 * @param claimSpecs the claims to request within this credential
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.4">OID4VP 1.0 §5.4 — DCQL Query</a>
 */
public record CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {}
