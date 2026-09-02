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
 * The decrypted wallet response of the {@code direct_post.jwt} response mode, where the wallet
 * encrypts its response to the verifier's ephemeral public key from {@code client_metadata}. The
 * payload carries either a {@code vp_token} or an {@code error} with its
 * {@code error_description}, so the unused members are {@code null}.
 *
 * @param mdocGeneratedNonce the mDoc session transcript nonce, taken from the JWE APU header
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1">OID4VP 1.0 §8.3.1 — Response Mode direct_post.jwt</a>
 */
public record DecryptedResponse(
        String vpToken, String state, String mdocGeneratedNonce, String error, String errorDescription) {}
