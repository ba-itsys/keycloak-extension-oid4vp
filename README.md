# keycloak-extension-oid4vp

Keycloak identity provider extension for login with EUDI-compatible digital identity wallets through [OpenID for Verifiable Presentations (OID4VP) 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

> This extension is under active development and is not production-ready. APIs, configuration keys and behavior can
> change without notice.

## Quick Start

### Build

```bash
mvn package -DskipTests
cp core/target/keycloak-extension-oid4vp.jar /opt/keycloak/providers/
```

`docker-compose.yml` mounts `core/target/keycloak-extension-oid4vp.jar`.

### Local Run

```bash
scripts/dev.sh --local-wallet
```

Local wallet setup, sandbox setup and script usage: [Development](docs/development.md).

## Features

Keycloak acts as an OID4VP verifier:

- same-device and cross-device wallet login flows
- SD-JWT VC and mDoc (`mso_mdoc`) verification
- SD-JWT issuer verification with `x5c` first, then the issuer keys of the credential's trust domain, then JWT VC issuer
  metadata (`kid`)
- DCQL-based credential requests
- `direct_post` and `direct_post.jwt` response modes
- verifier configuration for the high assurance profile, including encrypted wallet responses
- X.509-based verifier identification (`x509_san_dns`, `x509_hash`)
- claim mappers for user attributes and session notes
- transient wallet logins through Keycloak transient users (`doNotStoreUsers`)

## High Level Flow

1. At login, Keycloak allocates a `state` for each enabled browser flow and renders a same-device deep link, a
   cross-device QR code, or both. The `request_uri` carries the `state`.
2. The wallet fetches the `request_uri`, and Keycloak generates a signed request object for that fetch.
3. The wallet posts the presentation to the verifier endpoint and echoes the `state`.
4. After successful verification, Keycloak generates a single-use `response_code`.
5. The browser completes the login through `/complete-auth?state=...&response_code=...`. It must present that
   `response_code`, and the request must belong to the original Keycloak authentication session. The public `state`
   alone cannot drive completion.

SD-JWT VC issuer verification order:

1. `x5c`-based verification.
2. Without a usable `x5c` chain, the issuer keys published by the credential's trust domain.
3. JWT VC issuer metadata, used only when the identity provider references no trust material providers. The verifier
   resolves the signing key from `/.well-known/jwt-vc-issuer`, including `jwks_uri` documents, using the JOSE `kid`.

When trust material providers are configured, the verifier rejects a credential type that none of them serves.

See [Flow Details](docs/flow-details.md) and [Security](docs/security.md).

## Documentation

| Document                                          | Description                                                 |
|---------------------------------------------------|-------------------------------------------------------------|
| [Setup Guide](docs/setup.md)                      | Step-by-step configuration instructions                     |
| [Flow Details](docs/flow-details.md)              | Request flow through the code, error handling and diagrams  |
| [Configuration](docs/configuration.md)            | Reference of all configuration options                      |
| [Security Events](docs/events.md)                 | Keycloak events the extension fires and their details       |
| [SPI Reference](docs/spi-reference.md)            | Reference credential binding SPI                            |
| [UI Customization](docs/ui-customization.md)      | Theme and template customization                            |
| [Security](docs/security.md)                      | Security model, revocation and security events              |
| [Development](docs/development.md)                | Local setup, scripts and tests                              |
| [OIDF Conformance](docs/conformance.md)           | Running the OpenID conformance suite                        |
| [Troubleshooting](docs/troubleshooting.md)        | Common issues and solutions                                 |
| [Load Testing](loadtest/README.md)                | Load test setup                                             |

## Local Development

### Prerequisites

- **Keycloak**: `pom.xml` names the target version.
- **JDK**: `pom.xml` names the required Java version.
- **Maven**: The project builds with Maven.
- **Docker**: Integration tests and local container-based development need Docker (see `docker-compose.yml`).

### Checks

- **Formatting**: `mvn spotless:apply` applies the code style.
- **Verification**: `mvn verify` runs the unit tests and builds the project. Maven skips integration and conformance
  tests by default.
- **Unit tests:** `mvn test`
- **Integration/E2E tests:** `mvn verify -pl integration-tests -am -Pintegration-tests`. To select a single test class,
  add `-Dit.test='KeycloakOid4vpLoginE2eIT'`.
- **Conformance tests:** `mvn verify -pl conformance-tests -am -Pconformance-tests`

### Local Files

- **Demo realm import:** `core/src/test/resources/realm-wallet-demo-local.json`
- **Helper scripts:** `scripts/dev.sh`, `scripts/setup-local-realm.sh`, `scripts/run-keycloak-ngrok.sh`

## Contributing

Contributions are welcome. See the central
[Contributing Guide](https://github.com/ba-itsys/.github/blob/main/CONTRIBUTING.md).

- **Commit Guidelines**: We strictly follow [Conventional Commits](https://www.conventionalcommits.org/). The commit
  type (e.g., `feat`, `fix`, `docs`) drives our automated versioning and changelog generation. All commits must be
  signed off with `git commit -s` (DCO).
- **Pull Request Process**: Fork the repository, create a feature branch from `main`, and open a Pull Request against
  `main` (rebased on the latest `main`). Every bug fix or new feature should include corresponding tests.
- **Release Process**: [release-please](https://github.com/googleapis/release-please) automates releases. It parses the
  conventional commits from the merged history to create version bumps, changelogs and releases. See
  the [Release Process documentation](https://github.com/ba-itsys/.github/blob/main/docs/release-process.md) for details
  on commit types, validation and the full release flow.

## License

Apache License 2.0. See [LICENSE](LICENSE).
