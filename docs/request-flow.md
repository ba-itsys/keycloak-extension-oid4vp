# OID4VP Request Flow — Code Walkthrough

This document traces the OID4VP authorization request through the code for both same-device and cross-device flows.

## Key Concepts

### The `request_handle`

The `request_handle` is a unique, unguessable token generated once per rendered browser flow. It is the stable handle for the browser-side login attempt.

1. **Flow lookup** — maps the browser flow back to the stored flow context `{rootSessionId, tabId, effectiveClientId, responseUri, flow}`.
2. **Completion handle** — identifies which deferred authentication result `/complete-auth` should consume after a successful wallet callback.

**Format:** Random UUID. Generated when the login page is rendered, before any wallet fetches the request object.

**Lifecycle:** Generated during login page rendering → embedded in the `request_uri` path and, for cross-device, in the SSE status subscription → reused across multiple request-object fetches for the same browser flow → removed after the first successful callback consumes the flow.

**Security note:** The `request_handle` is not enough on its own to observe or finish the flow. Both `/cross-device/status` and `/complete-auth` use the stored `{rootSessionId, tabId}` from the single-use store to recover the original Keycloak authentication session and require the current browser request to be attached to that same auth session. In practice, security relies on both: a live one-time handle and the matching browser auth-session cookie.

### The `state` Parameter

The `state` parameter is a unique, unguessable token generated per created request object. It serves two purposes:

1. **Callback integrity** — the verifier checks that the `state` returned by the wallet matches the stored request context for that request object, preventing the callback from being rebound to a different request instance.
2. **Request binding** — maps the wallet's direct_post response back to the exact created request instance, especially important when the same `request_uri` is fetched multiple times before one callback arrives.

**Format:** `{tabId}.{random}` where `tabId` is Keycloak's auth session tab identifier and `random` is a fresh UUID-like random value. Generated when `/request-object/{requestHandle}` is fetched.

**Lifecycle:** Generated when the wallet fetches a request object → included in the signed request object JWT → returned by the wallet in the direct_post `state` form parameter → resolved back to a stored request context → discarded after TTL or after the flow is consumed.

**Security note:** The `state` value itself is not a secret — it is transmitted in signed request objects and form parameters. The flow's security does not rely on `state` being confidential. Instead, integrity is ensured by other layers: the request object is **signed** (preventing tampering with `state`, `nonce`, `response_uri`, and other claims), and when HAIP is enabled the wallet response is **encrypted** (protecting `vp_token` and `state` in transit). The `nonce` in the request object provides replay protection, and the KB-JWT (SD-JWT) / device authentication (mDoc) binds the presentation to the specific transaction.

**Difference from `request_handle`:** `request_handle` is stable for one browser flow and is used to recover or complete that flow later. `state` is per fetched request object and binds the wallet callback to one specific created request instance under that flow.

## Entry Point: Login Page

When a user clicks "Login with Wallet", Keycloak calls:

```
Oid4vpIdentityProvider.performLogin(AuthenticationRequest)
```

This method:

1. **Initializes login context** (`initializeLoginContext`) — computes `clientId` / `effectiveClientId`, chooses the auth-session tab ID used for flow binding, and captures the browser routing parameters needed to build the fallback form action
2. **Builds redirect flow data** (`buildRedirectFlowData`) — creates a separate stable `requestHandle` for each enabled flow (same-device and cross-device), stores the per-flow context in `Oid4vpRequestObjectStore`, builds the corresponding `request_uri` URLs
3. **Renders the login page** (`buildLoginFormResponse`) — passes wallet URLs, QR code, and SSE status URL to `login-oid4vp-idp.ftl`

The login page contains:
- Hidden state/request-handle fields used to keep the browser-side flow bound to the original Keycloak login attempt
- A same-device deep link (`openid4vp://...?request_uri=...`)
- A cross-device QR code encoding a similar URL (`openid4vp://...?request_uri=...`)
- JavaScript that opens an SSE connection to `/cross-device/status?request_handle=...` using the cross-device flow's stable request handle when that flow is enabled

**Key detail:** The `request_uri` points to `/endpoint/request-object/{requestHandle}`. The request handle is stable for the browser flow, but each request-object fetch creates a fresh request context with its own `state`, `nonce`, and response-encryption key when the effective `response_mode` is `direct_post.jwt`. The request object JWT itself expires quickly (default 10 seconds) to limit fetch/replay windows, but once a wallet has fetched it, the later callback is accepted as long as the stored request context and authentication session still exist.

## Phase 1: Wallet Fetches Request Object

```
Oid4vpIdentityProviderEndpoint.getRequestObject(requestHandle)
    or
Oid4vpIdentityProviderEndpoint.postRequestObject(requestHandle, walletNonce, walletMetadata)
    both call →
Oid4vpRequestObjectService.generateRequestObject(requestHandle, walletNonce, walletMetadata)
```

`generateRequestObject`:

1. Resolves the `requestHandle` → looks up the stored flow context `{rootSessionId, tabId, effectiveClientId, responseUri, flow}` from `Oid4vpRequestObjectStore`
2. Resolves the auth session from `rootSessionId` + `tabId` to ensure the login attempt is still active
3. Creates a fresh request context `{requestHandle, state, nonce, encryptionKeyJson, encryptionJwkThumbprint, flow}` and stores it under the new `state` (and `kid` when the effective `response_mode` is `direct_post.jwt`) before the response is returned to the wallet
4. Delegates to `Oid4vpRedirectFlowService.buildSignedRequestObject(params)` using that fresh request context:

```
Oid4vpRedirectFlowService.buildSignedRequestObject(RequestObjectParams)
```

This method:

1. **Resolves signing and response-encryption keys** — uses the configured x509 signing JWK when present, otherwise the realm signing key; when the effective `response_mode` is `direct_post.jwt`, it also generates or reuses the fresh per-request ECDH-ES response-encryption key
2. **Builds request claims** — `jti`, `iat`, `exp`, `iss`, `aud`, `client_id`, `response_type`, `response_mode`, `response_uri`, `nonce`, `state`, optional `wallet_nonce`, DCQL query, verifier info, and `client_metadata`. When `useIdTokenSubject` is enabled and HAIP is disabled, `response_type` becomes `vp_token id_token` and `scope=openid` is added; under HAIP, `useIdTokenSubject` is effectively disabled
3. **Builds `client_metadata`** — only for encrypted wallet responses: includes the public response-encryption JWK in `jwks`, the verifier's supported wallet-response encryption methods, and `vp_formats_supported`
4. **Normalizes DCQL trusted-authorities constraints** — if `trustedAuthoritiesMode` is enabled, the generated/manual DCQL query gets exactly one `trusted_authorities` type:
   - `etsi_tl` advertises the configured trust-list URL
   - `aki` advertises certificate key identifiers extracted from the configured trust list
   - `none` leaves `trusted_authorities` absent
   HAIP does not force this feature on; it remains explicit verifier configuration.
5. **Delegates compact JWS creation to `Oid4vpRequestObjectSigner`** — attaches `x5c` or public `jwk` headers as required by the chosen client-id scheme and signs through Keycloak key abstractions

Returns `SignedRequestObject(jwt, encryptionKeyJson)`. The returned `encryptionKeyJson` matches the freshly stored request context entry for that specific created request object.

6. **Encrypts if `wallet_metadata` is present** (POST only) — `Oid4vpRequestObjectService` parses the wallet metadata after signing and, when the wallet supplied a request-object encryption key, wraps the signed JWT in a JWE via `Oid4vpRequestObjectEncryptor.encrypt`. The `cty` header is set to `oauth-authz-req+jwt` to indicate a nested JWT. The HTTP content type remains `application/oauth-authz-req+jwt`.

## Phase 2: Wallet Posts VP Token

The wallet verifies the request, prompts the user, and POSTs the VP token.

Both same-device and cross-device wallets POST to the `response_uri` (direct_post). The endpoint handles both in the same method:

```
Oid4vpIdentityProviderEndpoint.handlePost(state, vpToken, encryptedResponse, error, errorDescription)
```

`handlePost`:

1. **Reads state** from the form body (OID4VP `direct_post` form parameter)
2. **KID-based resolution** (encrypted responses only) — whenever `encryptedResponse` is present, extracts the KID from the JWE header, resolves the full request context from `Oid4vpRequestObjectStore`, fills in the state if the wallet omitted it, and rejects the callback if the posted `state` disagrees with that request context
3. **Resolves auth session** from the request context's `{rootSessionId, tabId}`
4. **Decrypts** (when `response_mode=direct_post.jwt`) — decrypts the JWE using the request context's stored private key, extracts `vp_token`, `error`, `mdocGeneratedNonce`
5. **Error handling** — if the wallet sent an error, returns a JSON response with `redirect_uri` pointing to the error page (GET endpoint)
6. **Derives same-device vs cross-device behavior from the stored request context** — the callback does not trust a `flow` query parameter; it uses the `flow` value anchored behind the resolved request context
7. **Calls `processVpToken`** →

```
processVpToken(authSession, requestContext, state, vpToken, idToken, mdocGeneratedNonce, isCrossDeviceFlow)
```

8. **Verifies the credential** via `Oid4vpCallbackProcessor.process(requestContext, vpToken, idToken, mdocGeneratedNonce)`:

```
Oid4vpCallbackProcessor.process(requestContext, vpToken, idToken, mdocGeneratedNonce)
```

This:
- Validates that a request context was resolved for the callback
- Reads `clientId`, `nonce`, `responseUri`, and `encryptionJwkThumbprint` from that request context
- Reads the request-scoped configured credential types captured when the request object was created
- Passes `mdocGeneratedNonce` from the decrypted callback payload when present
- Calls `VpTokenProcessor.process(vpToken, clientId, nonce, responseUri, mdocGeneratedNonce, encryptionJwkThumbprint)`:
  - SD-JWT: `SdJwtVerifier.verify()` — delegates to Keycloak's `SdJwtVP.verify()` which performs:
    1. **Issuer signature verification** — validates the SD-JWT's JWS signature using the issuer's public key, resolved in this order:
       - `x5c` certificate-chain validation against the trust list (`X5cChainValidator`)
       - outside HAIP only: JWT VC issuer metadata lookup via `iss` + JOSE `kid` (`JwtVcIssuerMetadataResolver`), including `jwks_uri`
       - final direct trusted-certificate fallback for non-HAIP deployments that use self-signed or directly trusted issuer keys
    2. **Issuer JWT time checks** — `exp` (must not be expired), `nbf` (must be valid now), both with configurable clock skew (default 60s). No `iat` freshness check on the issuer JWT (old credentials are valid as long as `exp` holds)
    3. **Selective disclosure digest verification** — SHA-256 hashes of disclosed claims match the `_sd` digests in the issuer JWT
    4. **KB-JWT signature verification** — verifies the Key Binding JWT signature against the holder's public key from the credential's `cnf.jwk` claim
    5. **KB-JWT claim validation** — `aud` must match `clientId` (falls back to `response_uri` if primary check fails), `nonce` must match the expected nonce from the request object, `iat` must be fresh (default max age 300s + 60s clock skew), `exp`/`nbf` if present
    6. **KB-JWT `sd_hash` validation** — must equal SHA-256 of the unbound SD-JWT presentation (issuer JWT + disclosures, without the KB-JWT itself)
  - mDoc: `MdocVerifier.verifyWithTrustedCerts()` — validates MSO COSE_Sign1 issuer signature, MSO validity period (`validFrom`/`validUntil`), value digest integrity (SHA-256 of IssuerSignedItems vs MSO digests), device authentication signature via SessionTranscript binding, and extracts namespace-prefixed claims. The device authentication supports two SessionTranscript formats:
    - **OID4VP 1.0** (Appendix B.3.2.2): `[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]]` — the `jwk_thumbprint` is the RFC 7638 SHA-256 thumbprint of the HAIP encryption key from `client_metadata.jwks`, stored in the request context when the request object is created
    - **ISO 18013-7** (Annex B.4.4): `[null, null, [SHA-256(CBOR([client_id, mdoc_generated_nonce])), SHA-256(CBOR([response_uri, mdoc_generated_nonce])), nonce]]` — used as a fallback when `mdocGeneratedNonce` is present (extracted from JWE `apu` header) and the OID4VP 1.0 transcript does not verify
  - Checks revocation via `StatusListVerifier`
  - Validates the fetched trust list's `LoTEType` against the IdP's configured trust domain
- Validates issuer is allowed, credential type is allowed
- Rejects credentials whose `vct` / `docType` was not explicitly requested by this IdP's DCQL query
- Maps claims to `BrokeredIdentityContext`

9. **Stores deferred auth and returns redirect** — calls:

```
directPostService.storeAndSignal(authSession, requestHandle, context, isCrossDeviceFlow)
```

### Same-Device vs Cross-Device Differences

Both flows go through `Oid4vpDirectPostService.storeAndSignal`, which:

1. Serializes the `BrokeredIdentityContext` into the auth session (`DEFERRED_IDENTITY_NOTE`)
2. Also stores claims JSON separately (`DEFERRED_CLAIMS_NOTE`) because Keycloak's serializer loses nested Map types
3. Stores the deferred auth single-use object for both flows using the realm login timeout and, for cross-device only, stores a separate completion marker using `crossDeviceCompleteTtlSeconds`:
   - `oid4vp_deferred:{requestHandle}` → `{rootSessionId, tabId}` — used by `/complete-auth`
   - `oid4vp_complete:{requestHandle}` → `{completeAuthUrl}` — read by SSE polling until `/complete-auth` removes it
4. Removes the stable `requestHandle` entry. That flow-handle entry is the authoritative liveness check for all later `state` / `kid` lookups, so any leftover request-specific entries are rejected and lazily removed on access, which invalidates every outstanding request context for that flow and blocks replay after the first successful callback

The difference is in the response:

- **Same-device:** Returns `{"redirect_uri": "/complete-auth?request_handle=..."}`. The wallet opens this URL in the browser, which triggers `completeAuth`.
- **Cross-device:** Returns `200 OK` with `{}` body. The browser's SSE connection picks up the completion signal and navigates to `/complete-auth`.

### Completion: `/complete-auth`

Both flows converge at:

```
Oid4vpIdentityProviderEndpoint.completeAuth(requestHandle)
    → Oid4vpDirectPostService.completeAuth(requestHandle, callback, event)
```

`completeAuth`:

1. Reads `oid4vp_deferred:{requestHandle}` without consuming it yet → gets `{rootSessionId, tabId}`
2. Resolves the stored auth session from `rootSessionId` + `tabId`
3. Resolves the current browser auth session from Keycloak's auth-session cookie and requires it to match the stored session
4. Consumes `oid4vp_deferred:{requestHandle}` and the cross-device completion marker
5. Deserializes the `BrokeredIdentityContext` from `DEFERRED_IDENTITY_NOTE`
6. Restores claims from `DEFERRED_CLAIMS_NOTE`
7. Calls `callback.authenticated(context)` — Keycloak completes the login

### Cross-Device: SSE Browser Notification

Meanwhile, the browser has an open SSE connection:

```
Oid4vpIdentityProviderEndpoint.crossDeviceStatus(requestHandle)
    → Oid4vpCrossDeviceSseService.subscribe(requestHandle, eventSink, sse)
```

Before accepting the subscription, the endpoint resolves the auth session for the `requestHandle` and requires the current browser auth-session cookie to match it. The SSE service then polls `singleUseObjects` for `oid4vp_complete:{requestHandle}`. When found:
- Sends `event: complete` with `{"redirect_uri": "/complete-auth?request_handle=..."}` to the browser
- Leaves the completion marker in place so a reconnecting SSE client can observe the same completion event until `/complete-auth` consumes it

The browser JavaScript receives this and navigates to `/complete-auth?request_handle=...`, triggering the completion flow above.

The SSE implementation is node-local but state-shared: each node keeps one scheduler thread that polls Keycloak's shared single-use object store and fans out events to all SSE listeners currently connected to that node. This avoids a polling thread per browser connection and does not depend on cluster notifications, but it still requires the single-use store itself to be shared across nodes.

## Error Handling

Errors can occur at multiple points:

- **Wallet-side errors** (user denied consent, credential not available): The wallet may not POST to the verifier at all. The browser stays on the login page and the user can retry.
- **Server-side errors during direct_post** (revoked credential, invalid signature, etc.): The endpoint returns a JSON `{"redirect_uri": "/endpoint?error=...&error_description=..."}`. The wallet redirects the browser to this URL. The GET handler (`handleGet`) renders the Keycloak error page via `callback.error()`.

## Class Responsibilities

| Class | Role |
|-------|------|
| `Oid4vpIdentityProvider` | Login page rendering, session state init, DCQL query building |
| `Oid4vpIdentityProviderEndpoint` | Thin JAX-RS adapter for request-object, direct_post, SSE, and complete-auth routes |
| `Oid4vpRequestObjectService` | Request-object creation, wallet-metadata encryption, and request-context persistence |
| `Oid4vpEndpointResponseFactory` | JSON error payloads and wallet redirect responses |
| `Oid4vpRedirectFlowService` | Request claim assembly, client_metadata/encryption key generation, wallet authorization URL creation |
| `Oid4vpRequestObjectSigner` | Compact JWS creation for request objects using Keycloak key abstractions |
| `Oid4vpRequestObjectEncryptor` | Optional request-object JWE wrapping based on wallet metadata |
| `Oid4vpCallbackProcessor` | VP token verification orchestration, claim mapping to BrokeredIdentityContext |
| `VpTokenProcessor` | Credential format detection, SD-JWT/mDoc verification, revocation checks |
| `SdJwtVerifier` | SD-JWT signature + KB-JWT verification, disclosure resolution, verification-order policy (`x5c` first, metadata fallback outside HAIP) |
| `JwtVcIssuerMetadataResolver` | JWT VC issuer metadata discovery (`/.well-known/jwt-vc-issuer`), `jwks`/`jwks_uri` lookup, and bounded caching by response TTL and JWK `exp` |
| `MdocVerifier` | mDoc issuer/device auth verification, digest/validity checks, claim extraction |
| `MdocSessionTranscriptBuilder` | Builds OID4VP 1.0 and ISO 18013-7 SessionTranscript structures |
| `StatusListVerifier` | Token Status List fetching, caching, revocation bit checking |
| `TrustListProvider` | ETSI trust list fetching, certificate extraction, caching, optional JWT signature verification |
| `X5cChainValidator` | x5c certificate chain validation (shared by SD-JWT, mDoc, status list, trust list) |
| `Oid4vpDirectPostService` | Deferred auth storage for both flows, session restoration at `/complete-auth` |
| `Oid4vpCrossDeviceSseService` | Node-local SSE subscription and fan-out for cross-device completion |
| `Oid4vpRequestObjectStore` | Transient storage for stable flow handles, per-request contexts, state→request mappings, and KID→state mappings. Flow-handle removal invalidates all sibling request contexts without needing explicit per-flow state tracking |
| `Oid4vpAuthSessionResolver` | Auth session lookup from request object store (state→handle→session, rootSessionId→tabId) |
| `Oid4vpResponseDecryptor` | JWE decryption for direct_post.jwt responses |
| `Oid4vpRequestObjectEncryptor` | JWE encryption for request objects when wallet sends wallet_metadata |
| `DcqlQueryBuilder` | Builds DCQL queries from IdP mapper configurations |

## Configuration Notes

- `trustedAuthoritiesMode` is explicit verifier policy. `none` is the default, `etsi_tl` adds the trust-list URL to DCQL, and `aki` adds extension-derived certificate key identifiers from the trust list.
- If `trustListLoTEType` is configured, the fetched trust list must match this `LoTEType`, which keeps one OID4VP IdP instance bound to one trust domain. If it is empty, all LoTE types are accepted and a warning is logged.
- Within an accepted trust list, issuer verification uses certificates from `.../SvcType/.../Issuance` services only, while status-list verification uses `.../SvcType/.../Revocation` services only.
- The verifier trusts only the credential types it explicitly requested for that IdP.
- If `trustListSigningCertPem` is not configured, the trust-list JWT signature is not verified and the fetched trust list is trusted as-is. The code warns about that configuration but does not fail startup.
- When HAIP is enabled with `x509_hash`, the configured verifier certificate PEM is used for client ID derivation and request-object signing metadata. A full CA-issued chain is validated when present; a single non-self-signed leaf is also accepted, in which case issuer trust is expected to come from configured trust lists.
