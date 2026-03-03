# OID4VP Request Flow — Code Walkthrough

This document traces the OID4VP authorization request through the code for both same-device and cross-device flows.

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

Returns `SignedRequestObject(jwt, encryptionKeyJson)`. Back in the endpoint, if encryption was used, the KID is stored for later lookup.

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
- Calls `VpTokenProcessor.verify(vpToken, clientId, nonce, trustedCerts)`:
  - SD-JWT: `SdJwtVerifier.verify()` — validates issuer signature (x5c chain or direct trust), KB-JWT (audience, nonce, timestamps), extracts disclosed claims
  - mDoc: `MdocVerifier.verifyWithTrustedCerts()` — validates MSO COSE_Sign1 signature (x5c chain or direct trust), extracts namespace-prefixed claims
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
| `MdocVerifier` | mDoc COSE_Sign1 verification, namespace claim extraction |
| `StatusListVerifier` | Token Status List fetching, caching, revocation bit checking |
| `TrustListProvider` | ETSI trust list fetching, certificate extraction, caching |
| `X5cChainValidator` | x5c certificate chain validation (shared by SD-JWT, mDoc, status list) |
| `Oid4vpDirectPostService` | Deferred auth storage for both flows, session restoration at `/complete-auth` |
| `Oid4vpCrossDeviceSseService` | SSE long-polling for cross-device completion |
| `Oid4vpRequestObjectStore` | Transient storage for request handles, state→session mappings, KID→key mappings |
| `Oid4vpAuthSessionResolver` | Auth session lookup from request object store (state→session, rootSessionId→tabId) |
| `Oid4vpResponseDecryptor` | JWE decryption for direct_post.jwt responses |
| `DcqlQueryBuilder` | Builds DCQL queries from IdP mapper configurations |
