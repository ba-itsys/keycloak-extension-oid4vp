# OID4VP Request Flow — Code Walkthrough

This document traces the OID4VP authorization request through the code for both same-device and cross-device flows.

## Key Concepts

### The `state` Parameter

The `state` parameter is a unique, unguessable token generated per login attempt. It serves three purposes:

1. **CSRF protection** — the verifier checks that the `state` returned by the wallet matches the one stored in the auth session, preventing cross-site request forgery.
2. **Session binding** — maps the wallet's direct_post response back to the correct Keycloak auth session, especially important for cross-device flows where the wallet POST arrives without a session cookie.
3. **Single-use object key** — used as a suffix for transient storage keys (`oid4vp_state:{state}`, `oid4vp_deferred:{state}`, `oid4vp_complete:{state}`) that coordinate the deferred authentication flow.

**Format:** `{tabId}.{random}` where `tabId` is Keycloak's auth session tab identifier and `random` is 32 cryptographically random bytes encoded as base64url (no padding). Generated in `Oid4vpIdentityProvider.initializeSessionState()`.

**Lifecycle:** Generated at login page render → included in the signed request object JWT → returned by the wallet in the direct_post `state` form parameter → validated by `Oid4vpCallbackProcessor` against the auth session note → used as key for deferred auth storage → consumed by `/complete-auth` to finalize login.

**Security note:** The `state` value itself is not a secret — it is transmitted in URLs and form parameters. The flow's security does not rely on `state` being confidential. Instead, integrity is ensured by other layers: the request object is **signed** (preventing tampering with `state`, `nonce`, `response_uri`, and other claims), and when HAIP is enabled the wallet response is **encrypted** (protecting `vp_token` and `state` in transit). The `nonce` in the request object provides replay protection, and the KB-JWT (SD-JWT) / device authentication (mDoc) binds the presentation to the specific transaction.

## Entry Point: Login Page

When a user clicks "Login with Wallet", Keycloak calls:

```
Oid4vpIdentityProvider.performLogin(AuthenticationRequest)
```

This method:

1. **Initializes session state** (`initializeSessionState`) — generates `state`, `clientId`, stores them as auth notes
2. **Builds redirect flow data** (`buildRedirectFlowData`) — creates a `requestHandle`, stores it in `Oid4vpRequestObjectStore`, builds `request_uri` URLs for same-device and cross-device
3. **Renders the login page** (`buildLoginFormResponse`) — passes wallet URLs, QR code, and SSE status URL to `login-oid4vp-idp.ftl`

The login page contains:
- A hidden form that posts `vp_token`/`response` back to the Keycloak endpoint
- A same-device deep link (`openid4vp://...?request_uri=...&flow=same_device`)
- A cross-device QR code encoding a similar URL (`openid4vp://...?request_uri=...&flow=cross_device`)
- JavaScript that opens an SSE connection to `/cross-device/status?state=...`

**Key detail:** The `request_uri` points to `/endpoint/request-object/{requestHandle}`. The request object JWT is NOT pre-built — it's generated on demand when the wallet fetches the URI.

## Phase 1: Wallet Fetches Request Object

```
Oid4vpIdentityProviderEndpoint.getRequestObject(requestHandle, flow)
    or
Oid4vpIdentityProviderEndpoint.postRequestObject(requestHandle, flow, walletNonce)
    both call →
Oid4vpIdentityProviderEndpoint.generateRequestObject(requestHandle, flow, walletNonce)
```

`generateRequestObject`:

1. Resolves the `requestHandle` → looks up `{rootSessionId, tabId}` from `Oid4vpRequestObjectStore`
2. Resolves the auth session from `rootSessionId` + `tabId`
3. Reads `state`, `effectiveClientId` from auth notes
4. **Generates a fresh `nonce`** and stores it in the auth session — this prevents replay of VP tokens captured from earlier failed attempts
5. Computes `responseUri` — the URL where the wallet will POST the VP token:
   - Same-device: `/endpoint` (bare endpoint)
   - Cross-device: `/endpoint?flow=cross_device`
6. Delegates to `Oid4vpRedirectFlowService.buildSignedRequestObject(params)`:

```
Oid4vpRedirectFlowService.buildSignedRequestObject(RequestObjectParams)
```

This method:

1. **Builds base claims** (`buildBaseClaims`) — `jti`, `iat`, `exp`, `iss`, `aud`, `client_id`, `response_type=vp_token`, `response_mode` (`direct_post` or `direct_post.jwt`), `response_uri`, `nonce`, `state`
2. **Adds client_metadata** (`addClientMetadataClaim`) — only when HAIP is enabled: generates ephemeral ECDH-ES key pair, includes public key as JWKS in `client_metadata`
3. **Adds DCQL query + verifier_info** (`addDcqlAndVerifierInfo`)
4. **Resolves signing key** (`resolveSigningMaterial`) — uses x509 key from PEM config if available, otherwise the realm's default signing key
5. **Signs the JWT** — includes `x5c` certificate chain in the JWS header if configured

Returns `SignedRequestObject(jwt, encryptionKeyJson)`. Back in the endpoint, if encryption was used, the KID is stored for later lookup, and the JWK thumbprint (RFC 7638, SHA-256) of the encryption key's public part is stored in the auth session as `SESSION_ENCRYPTION_JWK_THUMBPRINT`. This thumbprint is later included in the OID4VP 1.0 SessionTranscript hash for mDoc device authentication verification.

7. **Encrypts if wallet_metadata present** (POST only) — if the wallet included a `wallet_metadata` form parameter with encryption keys (`jwks`), the signed JWT is wrapped in a JWE using ECDH-ES with the wallet's public key (`Oid4vpRequestObjectEncryptor.encrypt`). The `cty` header is set to `oauth-authz-req+jwt` to indicate a nested JWT. The HTTP content type remains `application/oauth-authz-req+jwt`.

## Phase 2: Wallet Posts VP Token

The wallet verifies the request, prompts the user, and POSTs the VP token.

Both same-device and cross-device wallets POST to the `response_uri` (direct_post). The endpoint handles both in the same method:

```
Oid4vpIdentityProviderEndpoint.handlePost(flow, state, vpToken, encryptedResponse, error, errorDescription)
```

`handlePost`:

1. **Reads state** from the form body (OID4VP `direct_post` form parameter)
2. **KID-based resolution** (HAIP only) — if state is missing but `encryptedResponse` is present, extracts the KID from the JWE header, looks up the encryption key + state from `Oid4vpRequestObjectStore`
3. **Resolves auth session** from the state→session index in `Oid4vpRequestObjectStore`
4. **Decrypts** (HAIP only) — decrypts the JWE using the ephemeral private key, extracts `vp_token`, `error`, `mdocGeneratedNonce`
5. **Error handling** — if the wallet sent an error, returns a JSON response with `redirect_uri` pointing to the error page (GET endpoint)
6. **Calls `processVpToken`** →

```
processVpToken(authSession, state, vpToken, isCrossDeviceFlow)
```

7. **Verifies the credential** via `Oid4vpCallbackProcessor.process(authSession, state, vpToken)`:

```
Oid4vpCallbackProcessor.process(authSession, state, vpToken)
    → processInternal(authSession, state, vpToken)
```

This:
- Validates state matches auth note
- Reads `mdocGeneratedNonce` and `encryptionJwkThumbprint` from auth session (stored during JWE decryption / request object generation in Phase 1–2)
- Calls `VpTokenProcessor.process(vpToken, clientId, nonce, responseUri, mdocGeneratedNonce, encryptionJwkThumbprint)`:
  - SD-JWT: `SdJwtVerifier.verify()` — delegates to Keycloak's `SdJwtVP.verify()` which performs:
    1. **Issuer signature verification** — validates the SD-JWT's JWS signature using the issuer's public key, resolved via x5c certificate chain validation (`X5cChainValidator`) or direct trust list lookup
    2. **Issuer JWT time checks** — `exp` (must not be expired), `nbf` (must be valid now), both with configurable clock skew (default 60s). No `iat` freshness check on the issuer JWT (old credentials are valid as long as `exp` holds)
    3. **Selective disclosure digest verification** — SHA-256 hashes of disclosed claims match the `_sd` digests in the issuer JWT
    4. **KB-JWT signature verification** — verifies the Key Binding JWT signature against the holder's public key from the credential's `cnf.jwk` claim
    5. **KB-JWT claim validation** — `aud` must match `clientId` (falls back to `response_uri` if primary check fails), `nonce` must match the expected nonce from the request object, `iat` must be fresh (default max age 300s + 60s clock skew), `exp`/`nbf` if present
    6. **KB-JWT `sd_hash` validation** — must equal SHA-256 of the unbound SD-JWT presentation (issuer JWT + disclosures, without the KB-JWT itself)
  - mDoc: `MdocVerifier.verifyWithTrustedCerts()` — validates MSO COSE_Sign1 issuer signature, MSO validity period (`validFrom`/`validUntil`), value digest integrity (SHA-256 of IssuerSignedItems vs MSO digests), device authentication signature via SessionTranscript binding, and extracts namespace-prefixed claims. The device authentication supports two SessionTranscript formats:
    - **OID4VP 1.0** (Appendix B.3.2.2): `[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]]` — the `jwk_thumbprint` is the RFC 7638 SHA-256 thumbprint of the HAIP encryption key from `client_metadata.jwks` (stored as `SESSION_ENCRYPTION_JWK_THUMBPRINT` during request object generation)
    - **ISO 18013-7** (Annex B.4.4): `[null, null, [SHA-256(CBOR([client_id, mdoc_generated_nonce])), SHA-256(CBOR([response_uri, mdoc_generated_nonce])), nonce]]` — used when `mdocGeneratedNonce` is present (extracted from JWE `apu` header). Tried first with OID4VP 1.0 as fallback.
  - Checks revocation via `StatusListVerifier`
- Validates issuer is allowed, credential type is allowed
- Maps claims to `BrokeredIdentityContext`

8. **Stores deferred auth and returns redirect** — calls:

```
directPostService.storeAndSignal(authSession, state, context, isCrossDeviceFlow)
```

### Same-Device vs Cross-Device Differences

Both flows go through `Oid4vpDirectPostService.storeAndSignal`, which:

1. Serializes the `BrokeredIdentityContext` into the auth session (`DEFERRED_IDENTITY_NOTE`)
2. Also stores claims JSON separately (`DEFERRED_CLAIMS_NOTE`) because Keycloak's serializer loses nested Map types
3. Stores two single-use objects:
   - `oid4vp_deferred:{state}` → `{rootSessionId, tabId}` — used by `/complete-auth`
   - `oid4vp_complete:{state}` → `{completeAuthUrl}` — consumed by SSE polling

The difference is in the response:

- **Same-device:** Returns `{"redirect_uri": "/complete-auth?state=..."}`. The wallet opens this URL in the browser, which triggers `completeAuth`.
- **Cross-device:** Returns `200 OK` with `{}` body. The browser's SSE connection picks up the completion signal and navigates to `/complete-auth`.

### Completion: `/complete-auth`

Both flows converge at:

```
Oid4vpIdentityProviderEndpoint.completeAuth(state)
    → Oid4vpDirectPostService.completeAuth(state, callback, event)
```

`completeAuth`:

1. Removes the `oid4vp_deferred:{state}` single-use object → gets `{rootSessionId, tabId}`
2. Resolves the auth session from `rootSessionId` + `tabId`
3. Deserializes the `BrokeredIdentityContext` from `DEFERRED_IDENTITY_NOTE`
4. Restores claims from `DEFERRED_CLAIMS_NOTE`
5. Calls `callback.authenticated(context)` — Keycloak completes the login

### Cross-Device: SSE Browser Notification

Meanwhile, the browser has an open SSE connection:

```
Oid4vpIdentityProviderEndpoint.crossDeviceStatus(state)
    → Oid4vpCrossDeviceSseService.buildSseResponse(state)
```

The SSE service polls `singleUseObjects` for `oid4vp_complete:{state}`. When found:
- Sends `event: complete` with `{"redirect_uri": "/complete-auth?state=..."}` to the browser

The browser JavaScript receives this and navigates to `/complete-auth?state=...`, triggering the completion flow above.

## Error Handling

Errors can occur at multiple points:

- **Wallet-side errors** (user denied consent, credential not available): The wallet may not POST to the verifier at all. The browser stays on the login page and the user can retry.
- **Server-side errors during direct_post** (revoked credential, invalid signature, etc.): The endpoint returns a JSON `{"redirect_uri": "/endpoint?error=...&error_description=..."}`. The wallet redirects the browser to this URL. The GET handler (`handleGet`) renders the Keycloak error page via `callback.error()`.

## Class Responsibilities

| Class | Role |
|-------|------|
| `Oid4vpIdentityProvider` | Login page rendering, session state init, DCQL query building |
| `Oid4vpIdentityProviderEndpoint` | JAX-RS endpoints: request-object, direct_post, SSE, complete-auth |
| `Oid4vpRedirectFlowService` | Request object JWT signing, client_metadata/encryption key generation |
| `Oid4vpCallbackProcessor` | VP token verification orchestration, claim mapping to BrokeredIdentityContext |
| `VpTokenProcessor` | Credential format detection, SD-JWT/mDoc verification, revocation checks |
| `SdJwtVerifier` | SD-JWT signature + KB-JWT verification, disclosure resolution |
| `MdocVerifier` | mDoc issuer/device auth verification, digest/validity checks, claim extraction |
| `MdocSessionTranscriptBuilder` | Builds OID4VP 1.0 and ISO 18013-7 SessionTranscript structures |
| `StatusListVerifier` | Token Status List fetching, caching, revocation bit checking |
| `TrustListProvider` | ETSI trust list fetching, certificate extraction, caching, optional JWT signature verification |
| `X5cChainValidator` | x5c certificate chain validation (shared by SD-JWT, mDoc, status list, trust list) |
| `Oid4vpDirectPostService` | Deferred auth storage for both flows, session restoration at `/complete-auth` |
| `Oid4vpCrossDeviceSseService` | SSE long-polling for cross-device completion |
| `Oid4vpRequestObjectStore` | Transient storage for request handles, state→session mappings, KID→key mappings |
| `Oid4vpAuthSessionResolver` | Auth session lookup from request object store (state→session, rootSessionId→tabId) |
| `Oid4vpResponseDecryptor` | JWE decryption for direct_post.jwt responses |
| `Oid4vpRequestObjectEncryptor` | JWE encryption for request objects when wallet sends wallet_metadata |
| `DcqlQueryBuilder` | Builds DCQL queries from IdP mapper configurations |
