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
| `clientIdScheme` | Client ID scheme for wallet authentication: `x509_san_dns` or `x509_hash`. | `x509_san_dns` |
| `x509CertificatePem` | PEM-encoded X.509 certificate chain (leaf + intermediates + private key). Used for signing request objects and as the verifier identity. | *(required)* |
| `x509SigningKeyJwk` | Optional JWK for request object signing. If not set, the private key from `x509CertificatePem` is used. | *(derived from PEM)* |
| `verifierInfo` | JSON string containing verifier attestation data (EUDI registration certificate). | *(none)* |

#### Trust & Verification

| Key | Description | Default |
|-----|-------------|---------|
| `enforceHaip` | Enforce HAIP compliance (ES256 signatures, encrypted responses via `direct_post.jwt`). | `true` |
| `additionalTrustedCertificates` | PEM-encoded certificates to trust in addition to the trust list. | *(none)* |
| `trustListUrl` | URL of an ETSI TS 119 602 trust list JWT. Used to obtain trusted issuer certificates for SD-JWT and mDoc signature verification. | *(none)* |
| `allowedIssuers` | Comma-separated list of allowed credential issuer identifiers, or `*` for any. | `*` |
| `allowedCredentialTypes` | Comma-separated list of allowed credential types (VCT/doctype), or `*` for any. | `*` |

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
- ngrok (for cross-device testing with real wallets)

### Quick Start

The `scripts/dev.sh` script handles everything in one command:

```bash
scripts/dev.sh
```

This will:
1. Build the extension (`mvn package -DskipTests`)
2. Generate a local realm config from the bundled sandbox certificates
3. Start the `oid4vc-dev` debugging proxy if available on PATH
4. Launch ngrok + Keycloak with the correct public hostname

The ngrok domain is auto-detected from the certificate's SAN DNS entry.

For local-only development without ngrok:

```bash
scripts/dev.sh --no-ngrok
```

#### Options

```
--pem <file>             Custom PEM file (default: sandbox/sandbox-ngrok-combined.pem)
--verifier-info <file>   Custom verifier info JSON (default: sandbox/sandbox-verifier-info.json)
--domain <name>          Override ngrok domain (default: from certificate SAN)
--no-build               Skip Maven build
--skip-realm             Skip realm config generation
--no-proxy               Disable oid4vc-dev proxy
--no-ngrok               Run Keycloak without ngrok (localhost only)
--ngrok-only             Start only the ngrok tunnel
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
