# keycloak-extension-oid4vp

A Keycloak identity provider extension that enables login with EUDI-compatible digital identity wallets via [OpenID for Verifiable Presentations (OID4VP) 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

> This extension is under active development and is not production-ready. APIs, configuration keys, and behavior may change without notice.

## Overview

The extension lets Keycloak act as an OID4VP verifier. It renders a wallet login page, generates request objects on demand, verifies the returned presentation, and completes the Keycloak login flow.

Supported capabilities:

- same-device and cross-device wallet login flows
- SD-JWT VC and mDoc (`mso_mdoc`) verification
- SD-JWT issuer verification with `x5c` first and JWT VC issuer-metadata (`kid`) fallback outside HAIP
- DCQL-based credential requests
- `direct_post` and `direct_post.jwt` response modes
- HAIP-oriented verifier configuration, including encrypted wallet responses
- X.509-based verifier identification (`x509_san_dns`, `x509_hash`)
- claim mappers for user attributes and session notes
- transient wallet logins through Keycloak transient users (`doNotStoreUsers`)

## Documentation

- [Configuration](docs/configuration.md)
- [Diagrams](docs/diagrams.md)
- [Request Flow Walkthrough](docs/request-flow.md)
- [Development](docs/development.md)
- [OIDF Conformance Testing](docs/conformance.md)
- [Load Testing](loadtest/README.md)

## How It Works

At login time, Keycloak creates a stable `request_handle` for each enabled browser flow and renders either a same-device deep link, a cross-device QR code, or both. The wallet fetches the `request_uri`, Keycloak generates a fresh signed request object for that fetch, and the wallet posts the resulting presentation to the verifier endpoint. After successful verification, Keycloak generates a single-use `response_code` and the browser completes the login through `/complete-auth`. The browser presents that `response_code`, and the request is bound to the original Keycloak authentication session, so the public `request_handle` alone cannot drive completion.

For SD-JWT VC, the verifier prefers `x5c`-based issuer verification. When HAIP is disabled and no usable `x5c` chain is present, it can resolve the issuer signing key from JWT VC issuer metadata at `/.well-known/jwt-vc-issuer`, including `jwks_uri` documents, using the JOSE `kid`.

For the full flow, security model, and request/state lifecycle, see [docs/request-flow.md](docs/request-flow.md).

## Requirements

- **Keycloak**: See `pom.xml` for the target version.
- **JDK**: See `pom.xml` for the required Java version.
- **Maven**: Used as the build tool.
- **Docker**: Required for integration tests and local container-based development (see `docker-compose.yml`).

## Installation

Build the extension and copy the shaded provider jar into Keycloak's `providers/` directory:

```bash
mvn package -DskipTests
cp core/target/keycloak-extension-oid4vp.jar /opt/keycloak/providers/
```

When using the provided `docker-compose.yml`, `core/target/keycloak-extension-oid4vp.jar` is mounted automatically.

## Local Development

For the fastest local setup, use:

```bash
scripts/dev.sh --local-wallet
```

For more details on local wallet setup, sandbox setup, and script usage, see [docs/development.md](docs/development.md).

### Common Commands

- **Formatting**: `mvn spotless:apply` (Ensures consistent code style).
- **Verification**: `mvn verify` (Runs the full test suite and builds the project).
- **Run only unit tests:** `mvn test`
- **Run integration/E2E tests:** skipped by default. Enable with the `integration-tests` profile: `mvn verify -pl integration-tests -am -Pintegration-tests`. A single test class can be selected with `-Dit.test='KeycloakOid4vpLoginE2eIT'`.
- **Run conformance tests:** skipped by default. Enable with the `conformance-tests` profile: `mvn verify -pl conformance-tests -am -Pconformance-tests`

### Important Local Files

- **Demo realm import:** `core/src/test/resources/realm-wallet-demo-local.json`
- **Helper scripts:** `scripts/dev.sh`, `scripts/setup-local-realm.sh`, `scripts/run-keycloak-ngrok.sh`

## License

Apache License 2.0. See [LICENSE](LICENSE).
