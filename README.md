> **Work in progress** -- This extension is under active development and **not production-ready**. APIs, configuration keys, and behaviour may change without notice.

# keycloak-extension-wallet

A Keycloak identity provider extension that enables login with EUDI-compatible digital identity wallets via [OpenID for Verifiable Presentations (OID4VP) 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Features

- Same-device and cross-device (QR code) wallet flows
- SD-JWT and mDoc (mso_mdoc) credential formats
- DCQL (Digital Credentials Query Language) for credential requests
- HAIP (High Assurance Interoperability Profile) compliance with encrypted responses
- X.509 certificate-based client authentication (`x509_san_dns`, `x509_hash`)
- Verifier attestation via `verifier_info` (EUDI registration certificates)
- Custom login theme with QR code display and SSE-based cross-device status updates
- IdP mappers for mapping credential claims to user attributes and session notes

## How It Works

The extension integrates as a Keycloak Identity Provider (IdP). When a user chooses to log in with their wallet, Keycloak initiates an [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) authorization request. The wallet fetches the request, collects the user's credential, and posts it back. Keycloak verifies the credential and completes the login.

Two flows are supported: **same-device** (wallet app on the same device as the browser) and **cross-device** (wallet on a different device, connected via QR code).

### Request Object: On-Demand Generation

The OID4VP request object (a signed JWT containing the authorization parameters) is **not pre-built** when the login page loads. Instead, the login page only contains a `request_uri` pointing to the Keycloak endpoint. The request object is generated on the fly when the wallet actually fetches that URI. This means the same QR code can be scanned multiple times (e.g., after a wallet error) and each fetch produces a fresh request object with new timestamps and encryption keys.

### Presentation Flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant K as Keycloak
    participant W as Wallet

    B->>K: 1. Click "Login with Wallet"
    K->>B: 2. Login page (deep link or QR code)
    B->>W: 3. Open wallet (tap link or scan QR)
    W->>K: 4. GET request_uri
    K->>W: 5. Signed request object JWT
    Note over W: 6. User consents, wallet builds vp_token
    W->>K: 7. POST vp_token to response_uri
    alt Same-device
        K->>W: 8a. Redirect URL
        B->>K: 9a. Browser follows redirect
    else Cross-device
        K->>W: 8b. 200 OK
        K->>B: 9b. SSE "complete" event with redirect_uri
        B->>K: 10b. GET /complete-auth?state=...
    end
    K->>B: Login complete
```

**Steps in detail:**

1. The user clicks the OID4VP identity provider on the Keycloak login page.
2. Keycloak generates a request token, stores a lightweight `{rootSessionId, tabId}` mapping, and renders the login page. In **same-device** mode, the page contains an `openid4vp://` deep link; in **cross-device** mode, a QR code encoding the same URL.
3. The user taps the deep link (same-device) or scans the QR code with a wallet on another device (cross-device).
4. The wallet fetches the request object from the `request_uri` (a Keycloak endpoint). The URL includes `?flow=same_device` or `?flow=cross_device`.
5. Keycloak generates and signs the request object JWT on demand, including the DCQL query, nonce, state, and (if HAIP) an ephemeral encryption key.
6. The wallet prompts the user to consent and builds the verifiable presentation token (`vp_token`).
7. The wallet POSTs the `vp_token` (or encrypted `response` if HAIP) to the `response_uri` specified in the request object. Keycloak verifies the credential and maps claims to user attributes.
8. **Same-device:** Keycloak returns a redirect URL; the wallet opens it in the browser and the login completes. **Cross-device:** Keycloak responds with `200 OK` and stores a completion signal in its single-use object store.
9. **Cross-device only:** The browser has an open SSE connection (`/cross-device/status?state=...`). It receives a `complete` event, navigates to `/complete-auth?state=...`, which restores the authentication session and finalizes the login.

### HAIP Mode (Encrypted Responses)

When `enforceHaip` is enabled, the flow includes response encryption:

- The request object includes a `client_metadata` claim with an ephemeral ECDH-ES public key.
- The wallet encrypts its response as a JWE (`direct_post.jwt` response mode) using that key.
- Keycloak decrypts the JWE using the matching private key (stored in the authentication session).
- A new encryption key pair is generated for each request object fetch, so retries get fresh keys.

### Wallet Nonce Binding

Some wallets support nonce binding ([OID4VP Section 7.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.3)). In this case:

1. The wallet POSTs to the `request_uri` with a `wallet_nonce` form parameter.
2. Keycloak generates a new request object that includes the `wallet_nonce` claim.
3. The wallet uses this nonce to bind the presentation to the specific request.

### Wallet Metadata (Request Object Encryption)

Wallets may optionally include a `wallet_metadata` form parameter when POSTing to the `request_uri`. If this metadata contains encryption keys (via `jwks`) and supported algorithms (`authorization_encryption_alg_values_supported`, `authorization_encryption_enc_values_supported`), Keycloak encrypts the signed request object as a JWE (sign-then-encrypt) using the wallet's public key. This is purely wallet-driven -- if the wallet does not send `wallet_metadata`, the request object is returned as a signed JWT only. Supported algorithms: ECDH-ES with A128GCM or A256GCM.

For a detailed code-level walkthrough of both flows, see [docs/request-flow.md](docs/request-flow.md).

## Requirements

- Keycloak 26.x (tested with 26.5.4)
- Java 21

## Installation

Build the extension and copy the provider JAR plus its dependencies into Keycloak's providers directory:

```bash
mvn package -DskipTests
cp target/providers/* /opt/keycloak/providers/
```

When using the provided `docker-compose.yml`, the `target/providers/` directory is mounted automatically.

## Configuration

The extension is configured as a Keycloak Identity Provider. All settings are configured in the IdP's provider config, either via the Admin UI or realm import JSON.

### Adding the Identity Provider

1. In the Keycloak Admin Console, go to **Identity Providers**
2. Select **OID4VP** from the provider list
3. Configure the settings below

Alternatively, add it via realm import JSON:

```json
{
  "identityProviders": [
    {
      "alias": "oid4vp",
      "displayName": "Sign in with Wallet",
      "providerId": "oid4vp",
      "enabled": true,
      "config": {
        "clientIdScheme": "x509_san_dns",
        "x509CertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "walletScheme": "openid4vp://",
        "enforceHaip": "true",
        "dcqlQuery": "{...}"
      }
    }
  ]
}
```

### Identity Provider Settings

#### Credential Request

| Key | Description | Default |
|-----|-------------|---------|
| `dcqlQuery` | DCQL query JSON defining which credentials to request. Auto-generated from IdP mappers if not set. | *(auto-generated)* |
| `credentialSetMode` | How credential sets are combined: `optional` (any one suffices) or `all` (all required). | `optional` |
| `credentialSetPurpose` | Human-readable purpose string included in the DCQL credential set. | *(none)* |

#### User Mapping

| Key | Description | Default |
|-----|-------------|---------|
| `userMappingClaim` | Claim from the SD-JWT credential used as the unique user identifier. | `sub` |
| `userMappingClaimMdoc` | Claim from the mDoc credential used as the unique user identifier. Falls back to `userMappingClaim` if not set. | *(falls back)* |

#### Flow Control

| Key | Description | Default |
|-----|-------------|---------|
| `sameDeviceEnabled` | Enable same-device flow (wallet on the same device as the browser). | `true` |
| `crossDeviceEnabled` | Enable cross-device flow (QR code scanned by wallet on another device). | `true` |
| `walletScheme` | URI scheme used to invoke the wallet app. | `openid4vp://` |

#### Client Authentication (X.509)

| Key | Description | Default |
|-----|-------------|---------|
| `clientIdScheme` | Client ID scheme for wallet authentication: `x509_san_dns` or `x509_hash`. Ignored when `enforceHaip` is `true` (forced to `x509_hash`). | `x509_san_dns` |
| `x509CertificatePem` | PEM-encoded X.509 certificate (see modes below). Used for client ID derivation and included in the request object's `x5c` header. | *(required for x509 schemes)* |
| `x509SigningKeyJwk` | JWK for request object signing. Normally auto-derived; only set this to override. | *(auto-derived)* |
| `verifierInfo` | JSON string containing verifier attestation data (EUDI registration certificate). | *(none)* |

**Two modes for `x509CertificatePem`:**

1. **Combined PEM (cert chain + private key)** -- The PEM contains the leaf certificate, optional intermediate certificates, and the private key. On startup, the extension extracts the private key into a signing JWK and strips the PEM down to certificates only. The private key is used to sign request objects, and the certificate chain is included in the JWS `x5c` header. This is the simplest setup and what `scripts/dev.sh` uses.

   ```
   -----BEGIN CERTIFICATE-----
   (leaf certificate)
   -----END CERTIFICATE-----
   -----BEGIN CERTIFICATE-----
   (intermediate CA certificate)
   -----END CERTIFICATE-----
   -----BEGIN PRIVATE KEY-----
   (EC private key)
   -----END PRIVATE KEY-----
   ```

2. **Cert-only PEM** -- The PEM contains only certificates (no private key). Request objects are signed with the Keycloak realm's default signing key. This works when the realm key pair is the same key pair that was certified by the CA -- i.e., you obtained the X.509 certificate for the realm's existing public key. The certificate is still included in the `x5c` header and used for client ID derivation.

   ```
   -----BEGIN CERTIFICATE-----
   (leaf certificate)
   -----END CERTIFICATE-----
   ```

#### Trust & Verification

| Key | Description | Default |
|-----|-------------|---------|
| `enforceHaip` | Enforce HAIP compliance (ES256 signatures, encrypted responses via `direct_post.jwt`). | `true` |
| `trustListUrl` | URL of an ETSI TS 119 602 trust list JWT. Used to obtain trusted issuer certificates for SD-JWT and mDoc signature verification. | *(none)* |
| `allowedIssuers` | Comma-separated list of allowed credential issuer identifiers, or `*` for any. | `*` |
| `allowedCredentialTypes` | Comma-separated list of allowed credential types (VCT/doctype), or `*` for any. | `*` |
| `clockSkewSeconds` | Clock skew tolerance (in seconds) for SD-JWT signature verification (`iat`, `exp`, `nbf` checks). | `60` |
| `kbJwtMaxAgeSeconds` | Maximum age (in seconds) for the Key Binding JWT `iat` claim. Limits how old the KB-JWT can be. | `300` |

#### Caching

Both the trust list and the token status list are cached based on the JWT `exp` claim. If no `exp` is present, the response is not cached. You can optionally cap the maximum cache duration.

| Key | Description | Default |
|-----|-------------|---------|
| `statusListMaxCacheTtlSeconds` | Maximum cache duration for token status lists (seconds). When set, the cache TTL is the minimum of this value and the JWT `exp`. | *(use JWT exp)* |
| `trustListMaxCacheTtlSeconds` | Maximum cache duration for the trust list (seconds). When set, the cache TTL is the minimum of this value and the JWT `exp`. | *(use JWT exp)* |

#### Cross-Device SSE (Server-Sent Events)

These settings control the SSE connection that keeps the browser informed during the cross-device QR code flow.

| Key | Description | Default |
|-----|-------------|---------|
| `ssePollIntervalMs` | How often the server polls for wallet completion (milliseconds). Lower values mean faster response but more load. | `2000` |
| `sseTimeoutSeconds` | Maximum time the SSE connection stays open before sending a timeout event. | `120` |
| `ssePingIntervalSeconds` | Interval between keep-alive ping events sent to the browser. | `10` |
| `crossDeviceCompleteTtlSeconds` | How long the cross-device completion signal is stored in Keycloak's single-use object store. Must be greater than `sseTimeoutSeconds`. | `300` |

### IdP Mappers

The extension provides two mapper types that can be added to the OID4VP identity provider:

- **OID4VP Claim to User Attribute** -- Maps a claim from the presented credential to a Keycloak user attribute.
- **OID4VP Claim to User Session Note** -- Maps a claim to a user session note (available to OIDC clients as a token claim).

Each mapper specifies a credential format (`dc+sd-jwt` or `mso_mdoc`), a claim path, and a credential type (VCT or doctype). When mappers are configured, the DCQL query is auto-generated from them unless `dcqlQuery` is explicitly set.

## Local Development

### Prerequisites

- Java 21, Maven 3.9+
- Docker
- [`oid4vc-dev`](https://github.com/dominikschlosser/oid4vc-dev) (recommended -- provides debugging proxy and local wallet)
- ngrok (only for cross-device testing with real wallets)

### Quick Start

The `scripts/dev.sh` script handles everything in one command. There are two main modes:

#### Local Wallet Mode (recommended for development)

```bash
scripts/dev.sh --local-wallet
```

This will:
1. Build the extension (`mvn package -DskipTests`)
2. Generate a local realm config using sandbox certificates and the local wallet's trust list
3. Start an `oid4vc-dev` wallet with pre-loaded PID credentials (SD-JWT + mDoc)
4. Start the `oid4vc-dev` debugging proxy (port 9090 -> Keycloak on 8080)
5. Launch Keycloak with `KC_HOSTNAME` set to the proxy URL

Access points:
- **Keycloak (via proxy):** http://localhost:9090
- **Admin console:** http://localhost:9090/admin (admin/admin)
- **Account console:** http://localhost:9090/realms/wallet-demo/account
- **oid4vc-dev dashboard:** http://localhost:9091 (shows intercepted OID4VP traffic)
- **Wallet UI:** http://localhost:8086

The wallet registers `openid4vp://` and `eudi-openid4vp://` URL scheme handlers,
so same-device flows open the wallet automatically.

#### Sandbox Mode (cross-device testing with real wallets)

```bash
scripts/dev.sh
```

This will:
1. Build the extension
2. Generate a local realm config from sandbox X.509 certificates
3. Start the `oid4vc-dev` debugging proxy if available on PATH
4. Launch ngrok + Keycloak with the correct public HTTPS hostname

The ngrok domain is auto-detected from the certificate's SAN DNS entry.

**Certificate material:** Sandbox mode requires a `sandbox/` directory (gitignored) with two files:

| File | Format | Description |
|------|--------|-------------|
| `sandbox-ngrok-combined.pem` | Combined PEM: leaf cert, optional intermediates, then EC private key (see [X.509 modes](#client-authentication-x509)) | Used for request object signing and `x5c` header. The certificate's SAN DNS entry determines the ngrok domain. |
| `sandbox-verifier-info.json` | JSON object (or JWT-wrapped registration certificate) matching the `verifier_info` claim format | Included in the request object as verifier attestation. |

Override the default location with `--pem` / `--verifier-info` flags, or set `SANDBOX_DIR` to point to a different directory:

```bash
SANDBOX_DIR=/opt/certs scripts/dev.sh
scripts/dev.sh --pem /tmp/my.pem --verifier-info /tmp/vi.json
```

#### Options

```
--local-wallet           Use local oid4vc-dev wallet (no ngrok needed)
--wallet-port <port>     oid4vc-dev wallet port (default: 8086)
--pem <file>             Custom PEM file (default: sandbox/sandbox-ngrok-combined.pem)
--verifier-info <file>   Custom verifier info JSON (default: sandbox/sandbox-verifier-info.json)
--domain <name>          Override ngrok domain (default: from certificate SAN)
--no-build               Skip Maven build
--skip-realm             Skip realm config generation
--no-proxy               Disable oid4vc-dev proxy
--no-ngrok               Run Keycloak without ngrok (localhost only)
--ngrok-only             Start only the ngrok tunnel
```

#### Examples

```bash
scripts/dev.sh --local-wallet                  # Local wallet + proxy (most common)
scripts/dev.sh --local-wallet --no-build       # Same, but skip rebuild
scripts/dev.sh                                 # Sandbox mode with ngrok
scripts/dev.sh --no-ngrok                      # Localhost only, no wallet, no ngrok
scripts/dev.sh --pem /tmp/my.pem --domain foo.ngrok-free.app
SANDBOX_DIR=/opt/certs scripts/dev.sh          # Custom cert location
```

### Manual Setup

```bash
mvn package -DskipTests
scripts/setup-local-realm.sh sandbox/sandbox-ngrok-combined.pem sandbox/sandbox-verifier-info.json
scripts/run-keycloak-ngrok.sh --domain wallet-test.ngrok.dev
```

### Running Tests

```bash
mvn verify                    # All tests (unit + integration)
mvn test                      # Unit tests only
mvn spotless:apply verify     # Format code, then run all tests
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
