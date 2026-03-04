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
 * Result of decrypting a JWE-encrypted wallet response ({@code direct_post.jwt} response mode).
 *
 * <p>When HAIP is enforced, the wallet encrypts its response using the verifier's ephemeral public
 * key from {@code client_metadata}. After decryption the payload contains either a {@code vp_token}
 * or an {@code error}/{@code error_description} pair.
 *
 * @param vpToken the decrypted VP token string, or {@code null} on error
 * @param mdocGeneratedNonce the mDoc session transcript nonce from the JWE APU header, or {@code null}
 * @param error the OAuth error code if the wallet reported an error, or {@code null}
 * @param errorDescription human-readable error description, or {@code null}
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Response Mode direct_post.jwt</a>
 */
public record DecryptedResponse(
        String vpToken, String idToken, String mdocGeneratedNonce, String error, String errorDescription) {}
