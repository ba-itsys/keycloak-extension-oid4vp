# OID4VP Request Flow — Code Walkthrough

This document traces the OID4VP authorization request through the code for both same-device and cross-device flows.

## Key Concepts

### The `response_code`

The `response_code` is a fresh, unguessable single-use secret generated in `Oid4vpDirectPostService.storeAndSignal` once the wallet's `direct_post` has been verified, per [OID4VP 1.0 §8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html). It binds completion to the specific verified submission and prevents anyone holding only the public `state` from driving `/complete-auth` (a session-fixation vector).

**Format:** 32 random bytes, Base64url-encoded (`SecretGenerator`). Generated once per `direct_post` completion.

**Lifecycle:** Generated during `storeAndSignal` → stored inside the `oid4vp_deferred:{state}` single-use object → embedded in the `complete-auth` URL that is delivered to the browser (same-device: the `direct_post` JSON `redirect_uri`; cross-device: the SSE `complete` event's `redirect_uri`) → presented back as the `response_code` query parameter at `/complete-auth`, where it is compared in constant time before any single-use object is consumed → discarded when the flow is consumed.

The browser learns the `response_code` only from the server (via the wallet redirect or SSE), never from the request object. The `state` is the public, stable correlator for the browser flow; the `response_code` is the confidential, per-submission secret that authorizes completion.

### The `state` Parameter

The `state` is the single identifier for a browser login flow. It is allocated once per flow when the login page is rendered (`Oid4vpIdentityProvider.createFlowEntry`) and serves every stage of the flow:

1. **Flow correlation** maps the browser flow back to the stored request context `{rootSessionId, tabId, effectiveClientId, responseUri, flow}`.
2. **Callback integrity** lets the verifier check that the `state` echoed by the wallet matches the stored request context, preventing the callback from being rebound to a different flow.
3. **Completion handle** identifies which deferred authentication result `/complete-auth` should consume after a successful wallet callback.

**Format:** `{flowTabId}.{UUID}` where `flowTabId` is Keycloak's auth session tab identifier and `UUID` is a fresh random value.

**Lifecycle:** Allocated when the login page is rendered → carried in the `request_uri` path (`/endpoint/request-object/{state}`) and advertised inside the signed request object → echoed back by the wallet in its `direct_post` `state` parameter → used by the browser for SSE polling (`/cross-device/status?state=...`) and `/complete-auth?state=...&response_code=...` → removed by `Oid4vpDirectPostService.completeAuth` after the first successful callback.

At render the flow also allocates the `nonce` and, for `direct_post.jwt`, the ephemeral response-encryption key, and stores one `RequestContextEntry` keyed by `oid4vp_state:{state}` (plus a `oid4vp_kid:{kid}` index). Because `state`, `nonce`, and the encryption key are allocated once at render, repeated `request_uri` fetches return the same `state`, `nonce`, and encryption key (stable per flow, not fresh per fetch). The signed request object is still built lazily on each fetch, so it can embed wallet-supplied `wallet_nonce` and `wallet_metadata`.

The `state` entry is the liveness anchor: while it exists the flow is live, and `Oid4vpDirectPostService.completeAuth` removes it (`removeRequestContext`) after a successful callback, which blocks replay.

**Security note:** The `state` value itself is not a secret. It is transmitted in signed request objects and form parameters. The flow's security does not rely on `state` being confidential. Instead, integrity is ensured by other layers: the request object is **signed** (preventing tampering with `state`, `nonce`, `response_uri`, and other claims), and when HAIP is enabled the wallet response is **encrypted** (protecting `vp_token` and `state` in transit). The `nonce` in the request object provides replay protection, and the KB-JWT (SD-JWT) / device authentication (mDoc) binds the presentation to the specific transaction. Two layers guard `/complete-auth`: (1) the single-use **`response_code`** generated during `direct_post`, which the browser must present, and (2) the stored `{rootSessionId, tabId}` browser-session check that requires the current browser auth-session cookie to match the Keycloak login attempt. `/cross-device/status` relies on the browser-session check.

## Entry Point: Login Page

When a user clicks "Login with Wallet", Keycloak calls:

```
Oid4vpIdentityProvider.performLogin(AuthenticationRequest)
```

This method:

1. **Initializes login context** (`initializeLoginContext`): computes `clientId` / `effectiveClientId`, chooses the auth-session tab ID used for flow binding, and captures the browser routing parameters needed to build the fallback form action
2. **Builds redirect flow data** (`buildRedirectFlowData`): allocates a `state` (and nonce + encryption key) for each enabled flow (same-device and cross-device), stores the per-flow context in `Oid4vpRequestObjectStore`, builds the corresponding `request_uri` URLs
3. **Renders the login page** (`buildLoginFormResponse`): passes wallet URLs, QR code, and SSE status URL to `login-oid4vp-idp.ftl`

The login page contains:
- A cross-device SSE config div exposing `data-state` (read by `oid4vp-cross-device-sse.js`) so the browser-side flow stays bound to the original Keycloak login attempt
- A same-device deep link (`openid4vp://...?client_id=...&request_uri=...`)
- A cross-device QR code encoding a similar URL (`openid4vp://...?client_id=...&request_uri=...`)
- JavaScript that opens an SSE connection to `/cross-device/status?state=...` using the cross-device flow's `state` when that flow is enabled

**Key detail:** The `request_uri` points to `/endpoint/request-object/{state}`. The `state`, `nonce`, and (for `direct_post.jwt`) response-encryption key are allocated once at render and stay stable across fetches, so repeated request-object fetches return the same values. The signed request object JWT itself expires quickly (default 10 seconds) to limit fetch/replay windows, but once a wallet has fetched it, the later callback is accepted as long as the stored request context and authentication session still exist.

## Phase 1: Wallet Fetches Request Object

The wallet URL rendered by the login page only advertises `client_id` and `request_uri`, so wallets normally fetch the request object with `GET /request-object/{state}`. The implementation also accepts `POST /request-object/{state}` so a wallet can send `wallet_nonce` and/or `wallet_metadata`.

```
Oid4vpIdentityProviderEndpoint.getRequestObject(state)
    or
Oid4vpIdentityProviderEndpoint.postRequestObject(state, walletNonce, walletMetadata)
    both call →
Oid4vpRequestObjectService.generateRequestObject(state, walletNonce, walletMetadata)
```

`generateRequestObject`:

1. Resolves the `state`: looks up the stored request context `{rootSessionId, tabId, effectiveClientId, responseUri, flow, state, nonce, encryptionKeyJson, encryptionJwkThumbprint}` from `Oid4vpRequestObjectStore`
2. Resolves the auth session from `rootSessionId` + `tabId` to ensure the login attempt is still active
3. Uses the stored `state`, `nonce`, and encryption key (allocated once at render, stable across fetches) rather than allocating fresh values per fetch
4. Delegates to `Oid4vpRedirectFlowService.buildSignedRequestObject(params)` using that request context:

```
Oid4vpRedirectFlowService.buildSignedRequestObject(RequestObjectParams)
```

This method:

1. **Resolves signing and response-encryption keys**: uses the configured x509 signing JWK when present, otherwise the realm signing key; when the effective `response_mode` is `direct_post.jwt`, it uses the per-flow ECDH-ES response-encryption key allocated at render
2. **Builds request claims**: `jti`, `iat`, `exp`, `iss`, `aud`, `client_id`, `response_type`, `response_mode`, `response_uri`, `nonce`, `state`, optional `wallet_nonce`, DCQL query, verifier info, and `client_metadata`. When `useIdTokenSubject` is enabled and HAIP is disabled, `response_type` becomes `vp_token id_token` and `scope=openid` is added; under HAIP, `useIdTokenSubject` is effectively disabled
3. **Builds `client_metadata`**: only for encrypted wallet responses, includes the public response-encryption JWK in `jwks`, the verifier's supported wallet-response encryption methods, and `vp_formats_supported`
4. **Normalizes DCQL trusted-authorities constraints**: if `trustedAuthoritiesMode` is enabled, the generated/manual DCQL query gets exactly one `trusted_authorities` type:
   - `etsi_tl` advertises the configured trust-list URL
   - `aki` advertises certificate key identifiers extracted from the configured trust list
   - `none` leaves `trusted_authorities` absent
   HAIP does not force this feature on; it remains explicit verifier configuration.
5. **Delegates compact JWS creation to `Oid4vpRequestObjectSigner`**: attaches `x5c` or public `jwk` headers as required by the chosen client-id scheme and signs through Keycloak key abstractions

Returns `SignedRequestObject(jwt, encryptionKeyJson)`. The returned `encryptionKeyJson` matches the per-flow request context entry stored at render.

6. **Encrypts if `wallet_metadata` is present** (POST only): `Oid4vpRequestObjectService` parses the wallet metadata after signing and, when the wallet supplied a request-object encryption key, wraps the signed JWT in a JWE via `Oid4vpRequestObjectEncryptor.encrypt`. The `cty` header is set to `oauth-authz-req+jwt` to indicate a nested JWT. The HTTP content type remains `application/oauth-authz-req+jwt`.

## Phase 2: Wallet Posts VP Token

The wallet verifies the request, prompts the user, and POSTs the VP token.

Both same-device and cross-device wallets POST to the `response_uri`. For `direct_post`, the form body carries `vp_token`, optional `id_token`, and `state`. For `direct_post.jwt`, the form body carries `response=<JWE/JWT>`; the decrypted payload inside that JWT/JWE must contain `state`, and the form body may also include a separate `state` parameter. The endpoint handles both in the same method:

```
Oid4vpIdentityProviderEndpoint.handlePost(state, vpToken, encryptedResponse, error, errorDescription)
```

`handlePost`:

1. **Reads form parameters** — `state`, `vp_token`, `id_token`, `response`, `error`, and `error_description`
2. **KID-based resolution** (encrypted responses only) — whenever the `response` form parameter is present, extracts the KID from the JWE header and resolves the full request context from `Oid4vpRequestObjectStore`
3. **Resolves auth session** from the request context's `{rootSessionId, tabId}`
4. **Decrypts and validates state** (when `response_mode=direct_post.jwt`) — decrypts the JWT/JWE from the `response` form parameter using the request context's stored private key, extracts `vp_token`, `id_token`, `state`, `error`, `error_description`, and `mdocGeneratedNonce`, requires the decrypted `state` to match the stored request context, and also rejects the callback if a separate posted `state` form parameter is present but differs from the decrypted `state`
5. **Error handling** — if the wallet sent an OAuth error (for example `access_denied`), returns a JSON body containing `error` and optional `error_description` without a `redirect_uri`, so the browser can remain on the login page and retry
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
directPostService.storeAndSignal(authSession, state, context, isCrossDeviceFlow)
```

### Same-Device vs Cross-Device Differences

Both flows go through `Oid4vpDirectPostService.storeAndSignal`, which:

1. Serializes the `BrokeredIdentityContext` into the auth session (`DEFERRED_IDENTITY_NOTE`)
2. Also stores claims JSON separately (`DEFERRED_CLAIMS_NOTE`) because Keycloak's serializer loses nested Map types
3. Generates a fresh single-use `response_code` and stores the deferred auth single-use object for both flows using the realm login timeout and, for cross-device only, stores a separate completion marker using `crossDeviceCompleteTtlSeconds`:
   - `oid4vp_deferred:{state}` → `{rootSessionId, tabId, response_code}`, used and verified by `/complete-auth`
   - `oid4vp_complete:{state}` → `{completeAuthUrl}`, read by SSE polling until `/complete-auth` removes it. The `completeAuthUrl` carries the `response_code`

The difference is in the response:

- **Same-device:** Returns `{"redirect_uri": "/complete-auth?state=...&response_code=..."}`. The wallet opens this URL in the browser, which triggers `completeAuth`.
- **Cross-device:** Returns `200 OK` with `{}` body. The browser's SSE connection picks up the completion signal and navigates to `/complete-auth?state=...&response_code=...`.

### Completion: `/complete-auth`

Both flows converge at:

```
Oid4vpIdentityProviderEndpoint.completeAuth(state, responseCode)
    → Oid4vpDirectPostService.completeAuth(state, responseCode, callback, event)
```

`completeAuth`:

1. Reads `oid4vp_deferred:{state}` without consuming it yet → gets `{rootSessionId, tabId, response_code}`, and **verifies the supplied `response_code` matches the stored one in constant time, rejecting before consuming anything** (so a known public `state` plus a wrong code cannot burn the legitimate single-use signal)
2. Resolves the stored auth session from `rootSessionId` + `tabId`
3. Resolves the current browser auth session from Keycloak's auth-session cookie and requires it to match the stored session
4. Consumes `oid4vp_deferred:{state}` and the cross-device completion marker
5. Deserializes the `BrokeredIdentityContext` from `DEFERRED_IDENTITY_NOTE`
6. Restores claims from `DEFERRED_CLAIMS_NOTE`
7. Calls `callback.authenticated(context)` — Keycloak completes the login

### Cross-Device: SSE Browser Notification

Meanwhile, the browser has an open SSE connection:

```
Oid4vpIdentityProviderEndpoint.crossDeviceStatus(state)
    → Oid4vpCrossDeviceSseService.subscribe(state, eventSink, sse)
```

Before accepting the subscription, the endpoint resolves the auth session for the `state` and requires the current browser auth-session cookie to match it. The SSE service then polls `singleUseObjects` for `oid4vp_complete:{state}`. When found:
- Sends `event: complete` with `{"redirect_uri": "/complete-auth?state=...&response_code=..."}` to the browser
- Leaves the completion marker in place so a reconnecting SSE client can observe the same completion event until `/complete-auth` consumes it

The browser JavaScript receives this and navigates to `/complete-auth?state=...&response_code=...`, triggering the completion flow above.

The SSE implementation is node-local but state-shared: each browser SSE connection runs on its own virtual thread and polls Keycloak's shared single-use object store until the flow completes, expires, or times out. No cluster notification channel is required, but the single-use store itself must be shared across nodes so reconnects can resume on any node.

## Error Handling

Errors can occur at multiple points:

- **Wallet-side errors** (user denied consent, credential not available): The wallet may not POST to the verifier at all, or it may POST an OAuth error. In both cases the endpoint returns a plain JSON error body without `redirect_uri`, the browser stays on the login page, and the user can retry.
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
| `Oid4vpCrossDeviceSseService` | Node-local SSE subscription handling for cross-device completion |
| `Oid4vpRequestObjectStore` | Transient storage for the per-flow request context keyed by `oid4vp_state:{state}`, plus a `oid4vp_kid:{kid}` index. The `state` entry is the liveness anchor: removing it invalidates the flow and blocks replay after the first successful callback |
| `Oid4vpAuthSessionResolver` | Auth session lookup from request object store (state→session, rootSessionId→tabId) |
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
