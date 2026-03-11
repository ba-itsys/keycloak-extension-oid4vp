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
 * Parameters for building an OID4VP Authorization Request Object (a signed JWT).
 *
 * <p>Passed from {@link de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderEndpoint} to
 * {@link de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpRedirectFlowService#buildSignedRequestObject}
 * each time the wallet fetches the {@code request_uri}. The stable browser/auth-session lookup is
 * the request handle, but the transaction-bound values (`state`, `nonce`, `responseUri`, and
 * optional response-encryption key for {@code direct_post.jwt}) belong to a single created request
 * object.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5 — Authorization Request</a>
 */
public record RequestObjectParams(
        String dcqlQuery,
        String verifierInfo,
        String clientId,
        String clientIdScheme,
        String responseUri,
        String state,
        String nonce,
        String x509CertPem,
        String x509SigningKeyJwk,
        String responseEncryptionKeyJson,
        String walletNonce,
        Oid4vpResponseMode responseMode,
        boolean useIdTokenSubject,
        boolean enforceHaip) {}
