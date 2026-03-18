# keycloak-extension-oid4vp

A Keycloak identity provider extension that enables login with EUDI-compatible digital identity wallets via [OpenID for Verifiable Presentations (OID4VP) 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

> This extension is under active development and is not production-ready. APIs, configuration keys, and behavior may change without notice.

## Overview

The extension lets Keycloak act as an OID4VP verifier. It renders a wallet login page, generates request objects on demand, verifies the returned presentation, and completes the Keycloak login flow.

Supported capabilities:

- same-device and cross-device wallet login flows
- SD-JWT VC and mDoc (`mso_mdoc`) verification
- DCQL-based credential requests
- `direct_post` and `direct_post.jwt` response modes
- HAIP-oriented verifier configuration, including encrypted wallet responses
- X.509-based verifier identification (`x509_san_dns`, `x509_hash`)
- claim mappers for user attributes and session notes
- transient wallet logins through Keycloak transient users (`doNotStoreUsers`)

## Documentation

- [Configuration](docs/configuration.md)
- [Request Flow Walkthrough](docs/request-flow.md)
- [Development](docs/development.md)
- [OIDF Conformance Testing](docs/conformance.md)

## How It Works

At login time, Keycloak creates a stable `request_handle` for each enabled browser flow and renders either a same-device deep link, a cross-device QR code, or both. The wallet fetches the `request_uri`, Keycloak generates a fresh signed request object for that fetch, and the wallet posts the resulting presentation to the verifier endpoint. After successful verification, the browser completes the login through `/complete-auth`, bound to the original Keycloak authentication session.

For the full flow, security model, and request/state lifecycle, see [docs/request-flow.md](docs/request-flow.md).

## Requirements

- Keycloak 26.x
- Java 21
- Maven 3.9+
- Docker for integration tests and local container-based development

## Installation

Build the extension and copy the provider jar plus its runtime dependencies into Keycloak's `providers/` directory:

```bash
mvn package -DskipTests
cp target/providers/* /opt/keycloak/providers/
```

When using the provided `docker-compose.yml`, `target/providers/` is mounted automatically.

## Development and Testing

For local wallet setup, sandbox setup, and script usage, see [docs/development.md](docs/development.md).

Common commands:

```bash
mvn test
mvn verify
mvn spotless:apply verify
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
