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

/**
 * The result of signing an OID4VP Authorization Request Object.
 *
 * @param jwt the compact-serialized signed JWT (JWS) containing the authorization request claims
 * @param encryptionKeyJson the ephemeral ECDH-ES private key as JSON (for later response decryption),
 *     or {@code null} if HAIP response encryption is not enabled
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1">OID4VP 1.0 §5.1 — Signed Request Object</a>
 */
public record SignedRequestObject(String jwt, String encryptionKeyJson) {}
