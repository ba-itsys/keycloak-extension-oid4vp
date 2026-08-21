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

At render the flow also allocates the `nonce` and, for `direct_post.jwt`, the ephemeral response-encryption key, and stores one `RequestContextEntry` keyed by `oid4vp_state:{state}`. The encryption key's `kid` is set to the `state`, so the cleartext JWE header of an encrypted callback identifies the request context without a separate index. Because `state`, `nonce`, and the encryption key are allocated once at render, repeated `request_uri` fetches return the same `state`, `nonce`, and encryption key (stable per flow, not fresh per fetch). The signed request object is still built lazily on each fetch, so it can embed wallet-supplied `wallet_nonce` and `wallet_metadata`.

The `state` entry is the liveness anchor: while it exists the flow is live, and `Oid4vpDirectPostService.completeAuth` removes it (`removeRequestContext`) after a successful callback, which blocks replay. An attempt that ended without completing is removed too, once the End-User has been handed back to the login page at `/failed` (`consumeFailure`), so an attempt nobody is waiting for any more stops serving its request object and stops accepting a presentation for the rest of the login timeout. Both ways a presentation can end lead there: the wallet reporting an error response, and the verifier rejecting the presentation it received.

**Security note:** The `state` value itself is not a secret. It is transmitted in signed request objects and form parameters. The flow's security does not rely on `state` being confidential. Instead, integrity is ensured by other layers: the request object is **signed** (preventing tampering with `state`, `nonce`, `response_uri`, and other claims), and with the `direct_post.jwt` response mode the wallet response is **encrypted** (protecting `vp_token` and `state` in transit). The `nonce` in the request object provides replay protection, and the KB-JWT (SD-JWT) / device authentication (mDoc) binds the presentation to the specific transaction. Two layers guard `/complete-auth`: (1) the single-use **`response_code`** generated during `direct_post`, which the browser must present, and (2) the stored `{rootSessionId, tabId}` browser-session check that requires the current browser auth-session cookie to match the Keycloak login attempt. `/cross-device/status` relies on the browser-session check. The flow is also **single-completion**: the first verified `direct_post` for a `state` establishes the identity and later submissions to the same `state` are ignored, which limits a presentation injected to a known `state` (the residual cross-device risk, since `state` travels in the public `request_uri`) from overwriting it. One authentication session carries several live states at a time, one per rendered flow, so the deferred result is stored under an auth note named after its own `state` (`OID4VP_DEFERRED_IDENTITY:{state}`, `OID4VP_DEFERRED_CLAIMS:{state}`): a presentation answering another state of the same authentication session establishes its own identity and cannot become the one `/complete-auth` reads back for this state.

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
2. **Builds request claims**: `jti`, `iat`, `exp`, `iss`, `aud`, `client_id`, `response_type`, `response_mode`, `response_uri`, `nonce`, `state`, optional `wallet_nonce`, DCQL query, verifier info, and `client_metadata`. The `response_type` is always `vp_token`
3. **Builds `client_metadata`**: only for encrypted wallet responses, includes the public response-encryption JWK in `jwks`, the verifier's supported wallet-response encryption methods, and `vp_formats_supported`
4. **Adds DCQL trusted-authorities constraints per credential**: every credential entry advertises what the trust material identity providers serving its credential type expose, as `etsi_tl` for a trust list URL and `aki` for certificate key identifiers. A credential whose trust domain has nothing to advertise, or whose provider leaves `advertiseTrustedAuthorities` empty, carries no `trusted_authorities` member. Per OID4VP 1.0 §6.1.1 the entries are alternatives: a credential matches when it matches one value of one entry.
5. **Delegates compact JWS creation to `Oid4vpRequestObjectSigner`**: attaches `x5c` or public `jwk` headers as required by the chosen client-id scheme and signs through Keycloak key abstractions

Returns `SignedRequestObject(jwt, encryptionKeyJson)`. The returned `encryptionKeyJson` matches the per-flow request context entry stored at render.

6. **Encrypts if `wallet_metadata` is present** (POST only): `Oid4vpRequestObjectService` parses the wallet metadata after signing and, when the wallet supplied a request-object encryption key, wraps the signed JWT in a JWE via `Oid4vpRequestObjectEncryptor.encrypt`. The `cty` header is set to `oauth-authz-req+jwt` to indicate a nested JWT. The HTTP content type remains `application/oauth-authz-req+jwt`.

## Phase 2: Wallet Posts VP Token

The wallet verifies the request, prompts the user, and POSTs the VP token.

Both same-device and cross-device wallets POST to the `response_uri`. For `direct_post`, the form body carries `vp_token` and `state`. For `direct_post.jwt`, the form body carries `response=<JWE/JWT>`; the decrypted payload inside that JWT/JWE must contain `state`, and the form body may also include a separate `state` parameter. The endpoint handles both in the same method:

```
Oid4vpIdentityProviderEndpoint.handlePost(state, vpToken, encryptedResponse, error, errorDescription)
```

`handlePost`:

1. **Reads form parameters**: `state`, `vp_token`, `response`, `error`, and `error_description`
2. **Request-context resolution** — resolves the full request context from `Oid4vpRequestObjectStore` by the posted `state`; when an encrypted response omits the `state` form parameter, the KID from the JWE header is used instead, because the response-encryption key's `kid` equals the flow `state`
3. **Resolves auth session** from the request context's `{rootSessionId, tabId}`
4. **Decrypts and validates state** (when `response_mode=direct_post.jwt`) — decrypts the JWT/JWE from the `response` form parameter using the request context's stored private key, extracts `vp_token`, `state`, `error`, `error_description`, and `mdocGeneratedNonce`, requires the decrypted `state` to match the stored request context, and also rejects the callback if a separate posted `state` form parameter is present but differs from the decrypted `state`
5. **Error handling** — if the wallet sent an OAuth error (for example `access_denied`), records it server-side and answers with HTTP 200 and, in a same-device flow, the `redirect_uri` the wallet must follow to hand the End-User back to `/failed`
6. **Derives same-device vs cross-device behavior from the stored request context** — the callback does not trust a `flow` query parameter; it uses the `flow` value anchored behind the resolved request context
7. **Calls `processVpToken`** →

```
processVpToken(authSession, requestContext, state, vpToken, mdocGeneratedNonce, isCrossDeviceFlow)
```

8. **Verifies the credential** via `Oid4vpCallbackProcessor.process(requestContext, vpToken, mdocGeneratedNonce)`:

```
Oid4vpCallbackProcessor.process(requestContext, vpToken, mdocGeneratedNonce)
```

This:
- Validates that a request context was resolved for the callback
- Reads `clientId`, `nonce`, `responseUri`, and `encryptionJwkThumbprint` from that request context
- Reads the request-scoped configured credential types captured when the request object was created
- Passes `mdocGeneratedNonce` from the decrypted callback payload when present
- Calls `VpTokenProcessor.process` with the `vp_token`, the `clientId`, `nonce`, `responseUri` and `encryptionJwkThumbprint` of the request context, the `mdocGeneratedNonce` of the callback, and the requested credentials:
  - SD-JWT: `SdJwtVerifier.verify()` — delegates to Keycloak's `SdJwtVP.verify()` which performs:
    1. **Issuer signature verification** — validates the SD-JWT's JWS signature using the issuer's public key, resolved in this order:
       - `x5c` certificate-chain validation against the resolved trust material: a pinned trusted leaf certificate bound to the credential's `iss`, or a PKIX path to the trust anchors with `iss` matching a subject alternative name of the leaf (`ResolvedTrust.validateIssuerChain`)
       - the issuer keys the credential's trust domain publishes, matched on `iss` and JOSE `kid`
       - when no trust material providers are configured at all: JWT VC issuer metadata lookup via `iss` + `kid` (`JwtVcIssuerMetadataResolver`), including `jwks_uri`
    2. **Issuer JWT time checks** — `exp` (must not be expired), `nbf` (must be valid now), both with configurable clock skew (default 60s). No `iat` freshness check on the issuer JWT (old credentials are valid as long as `exp` holds)
    3. **Selective disclosure digest verification** — SHA-256 hashes of disclosed claims match the `_sd` digests in the issuer JWT
    4. **KB-JWT signature verification** — verifies the Key Binding JWT signature against the holder's public key from the credential's `cnf.jwk` claim
    5. **KB-JWT claim validation** — `aud` must match `clientId` (falls back to `response_uri` if primary check fails), `nonce` must match the expected nonce from the request object, `iat` must be fresh (default max age 300s + 60s clock skew), `exp`/`nbf` if present
    6. **KB-JWT `sd_hash` validation** — must equal SHA-256 of the unbound SD-JWT presentation (issuer JWT + disclosures, without the KB-JWT itself)
  - mDoc: `MdocVerifier.verifyPresentation()` validates the MSO COSE_Sign1 issuer signature, the value digest integrity (the digest algorithm the MSO declares, over the IssuerSignedItems), the MSO validity period (`validFrom`/`validUntil` within the configured clock skew, and a presentation whose MSO carries no `validityInfo` is rejected), and the device authentication signature via SessionTranscript binding, then extracts namespace-prefixed claims. The device authentication supports two SessionTranscript formats:
    - **OID4VP 1.0** (Appendix B.2.6.1): `[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]]` — the `jwk_thumbprint` is the RFC 7638 SHA-256 thumbprint of the response encryption key from `client_metadata.jwks`, stored in the request context when the request object is created
    - **ISO 18013-7** (Annex B.4.4): `[null, null, [SHA-256(CBOR([client_id, mdoc_generated_nonce])), SHA-256(CBOR([response_uri, mdoc_generated_nonce])), nonce]]` — used as a fallback when `mdocGeneratedNonce` is present (extracted from JWE `apu` header) and the OID4VP 1.0 transcript does not verify
  - Checks revocation via `StatusListVerifier`
  - The referenced ETSI trust list identity providers validate their trust list's `LoTEType` against their configured trust domain while resolving trust material
- Validates issuer is allowed, credential type is allowed
- Rejects credentials whose `vct` / `docType` was not explicitly requested by this IdP's DCQL query
- Maps claims to `BrokeredIdentityContext`

9. **Stores deferred auth and returns redirect** — calls:

```
directPostService.storeAndSignal(authSession, state, context, isCrossDeviceFlow)
```

### What the Verifier Accepts Beyond the Specification

The verifier accepts three shapes OID4VP 1.0 does not require, so that wallets in the field interoperate. Each one widens what a presentation may look like, and each one is listed here because nothing in the configuration reveals it.

**Key Binding JWT audience.** The `aud` of a Key Binding JWT is the Client Identifier (OID4VP 1.0, Appendix B.3.6). Wallets disagree on this: some bind to the `client_id`, others to the `response_uri`. `VpTokenProcessor` verifies against the configured `client_id` and then retries once against the `response_uri` of the same request. Both values belong to this verifier and travel inside the signed request object, so a presentation still binds to one transaction of one verifier.

**VP token shape.** The `vp_token` is a JSON object mapping each DCQL credential id to an array of presentations, and the array holds exactly one presentation because the generated queries carry no `multiple` (OID4VP 1.0 §8.1). `VpTokenProcessor` also accepts a bare presentation string in place of that object and attributes it to the requested credential when the query requests exactly one. Several presentations under one credential id are each verified and the first one is used, so an invalid one among them still fails the login.

**mDoc DeviceResponse.** Every presented mDoc arrives in a `DeviceResponse` of its own, one per credential query (high assurance profile 1.0, section 5.3.1). `MdocVerifier` reads the first document of a response and ignores further documents as well as the `status` and `documentErrors` members of the response.

### Same-Device vs Cross-Device Differences

Both flows go through `Oid4vpDirectPostService.storeAndSignal`, which:

1. **Single-completion guard:** if a verified result is already recorded for this `state` (its `oid4vp_deferred:{state}` signal still exists, i.e. `/complete-auth` has not consumed it yet), it returns that existing completion idempotently and stores nothing new. The first verified presentation for a `state` wins, so a later presentation submitted to a known `state` (for example an attacker's own credential) cannot replace the identity the first wallet established, while a wallet can still safely retry its own `direct_post`. Only a successfully verified presentation reaches this method, so a failed one never locks the flow and can be retried.
2. Serializes the `BrokeredIdentityContext` into the auth session (`DEFERRED_IDENTITY_NOTE`)
3. Also stores claims JSON separately (`DEFERRED_CLAIMS_NOTE`) because Keycloak's serializer loses nested Map types
4. Generates a fresh single-use `response_code` and stores the deferred auth single-use object for both flows using the realm login timeout and, for cross-device only, stores a separate completion marker using `crossDeviceCompleteTtlSeconds`:
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

Both ways a presentation can end travel the back channel, so neither moves the browser by itself. A same-device wallet is therefore answered with the `redirect_uri` it must follow, exactly like a completed login, and a cross-device wallet with the empty object a completed cross-device login returns, because there the browser is on another device and the failure URL is published on the SSE stream instead. Why the login ended is a verification message rather than something a wallet or an End-User can act on, so by default it stays on the `LOGIN_ERROR` event and in the server-side failure record. The URL points at `/failed`, which reads that record (never its query parameters), drops the attempt's request context, and returns the End-User to the login page:

- **Wallet-reported errors** (user denied consent, credential not available): answered with HTTP 200, because the Response URI processed the Authorization Error Response successfully. `/failed` ends the login with `callback.cancelled()`, so the login page shows the standard "access denied" message and the user can retry or pick another method.
- **Presentations the verifier rejects** (revoked credential, invalid signature, unsatisfied DCQL): answered with HTTP 200 by default, because the Response URI processed the response and refused what it found. A wallet reads the status before the body, so anything else aborts the submission and the `redirect_uri` is never followed. The identity provider option `rejectionResponse` switches this to `error`, which answers HTTP 400 with the `error` and `error_description` beside that `redirect_uri`. §8.2 permits both, and a wallet-reported error is answered with 200 either way. `/failed` ends the login with `callback.error()` naming `oid4vpPresentationRejected`, so the End-User learns the presentation was rejected while the verification message itself stays on the login event.
- **Posts that never got as far as being verified** (unknown state, undecryptable response, an unencrypted response where encryption is required): answered with a plain HTTP 400 error and no `redirect_uri`. Nothing about such a post proves it came from the wallet whose login it names, so it must not be able to end that login.

There is no `GET` handler on the response URI itself. A wallet that redirected an error there by itself rather than posting it would arrive with nothing that proves it is the End-User's browser or that the error it names is the one that happened, so such a request cannot be allowed to end a login.

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
| `SdJwtVerifier` | SD-JWT signature + KB-JWT verification, disclosure resolution, verification-order policy (`x5c` first, then the trust domain's issuer keys, then metadata) |
| `JwtVcIssuerMetadataResolver` | JWT VC issuer metadata discovery (`/.well-known/jwt-vc-issuer`), `jwks`/`jwks_uri` lookup, and bounded caching by response TTL and JWK `exp` |
| `MdocVerifier` | mDoc issuer/device auth verification, digest/validity checks, claim extraction |
| `MdocSessionTranscriptBuilder` | Builds OID4VP 1.0 and ISO 18013-7 SessionTranscript structures |
| `StatusListVerifier` | Token Status List fetching, caching, revocation bit checking |
| `EtsiTrustListIdentityProvider` | Trust material identity provider (`etsi-trust-list`): trust anchors from an ETSI trust list URL and/or a pasted PEM bundle, LoTE type enforcement |
| `Oid4vpTrustMaterialResolver` | Resolves trust material identity providers by alias and aggregates their trust into `ResolvedTrust` |
| `TrustListProvider` | ETSI trust list fetching, certificate extraction, caching, optional JWT signature verification |
| `X509CertificateChainValidator` | PKIX x5c certificate chain validation (mirror of Keycloak main, shared by SD-JWT, mDoc, status list) |
| `X5cChainValidator` | JWT signature verification against pinned certificates (status list, trust list) |
| `Oid4vpDirectPostService` | Deferred auth storage for both flows, session restoration at `/complete-auth` |
| `Oid4vpCrossDeviceSseService` | Node-local SSE subscription handling for cross-device completion |
| `Oid4vpRequestObjectStore` | Transient storage for the per-flow request context keyed by `oid4vp_state:{state}`. The response-encryption key's `kid` equals the `state`, so encrypted callbacks resolve through the same entry. The `state` entry is the liveness anchor: removing it invalidates the flow and blocks replay after the first successful callback |
| `Oid4vpAuthSessionResolver` | Auth session lookup from request object store (state→session, rootSessionId→tabId) |
| `Oid4vpResponseDecryptor` | JWE decryption for direct_post.jwt responses |
| `Oid4vpRequestObjectEncryptor` | JWE encryption for request objects when the wallet_metadata names an encryption key |
| `DcqlQueryBuilder` | Builds DCQL queries from IdP mapper configurations |

## Configuration Notes

- Trust configuration lives on trust material identity providers (`etsi-trust-list`), referenced from the OID4VP IdP via `trustMaterialIdps`. This mirrors the trust material delegation model of upstream Keycloak's OID4VP work.
- Trust is resolved per credential: a trust material identity provider serves the credential types declared in `servedCredentialTypes`, or every type while the field is empty. A credential is verified against the material of the providers serving the type requested under the DCQL credential id it was presented for, and its DCQL entry advertises the `trusted_authorities` of those providers.
- If `trustListLoTEType` is configured on a trust material identity provider, the fetched trust list must match this `LoTEType`, which keeps one provider instance bound to one trust domain. If it is empty, all LoTE types are accepted.
- Within an accepted trust list, issuer verification uses certificates from `.../SvcType/.../Issuance` services only, while status-list verification uses `.../SvcType/.../Revocation` services only.
- The verifier trusts only the credential types it explicitly requested for that IdP.
- If `trustListSigningCertPem` is not configured, the trust-list JWT signature is not verified and the fetched trust list is trusted as-is. The code warns about that configuration but does not fail startup.
- With a certificate-bound `clientIdScheme`, the configured verifier certificate PEM is used for client ID derivation and for the request object `x5c` header. Because the verifier emits that chain, every certificate has to be currently valid and each one has to be signed by the next. Whether the certificate is acceptable is the wallet's decision against its own relying party trust list, so a self-signed or lone leaf certificate is warned about rather than rejected. Issuer trust comes from the configured trust material identity providers.
