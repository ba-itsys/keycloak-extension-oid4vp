# Development

## Prerequisites

- Java 21
- Maven 3.9+
- Docker
- [`oid4vc-dev`](https://github.com/dominikschlosser/oid4vc-dev) for local wallet-based development
- `ngrok` for public HTTPS testing with real wallets

## Quick Start

### Local Wallet Mode

```bash
scripts/dev.sh --local-wallet
```

This mode:

- builds the extension
- generates a local realm config
- starts an `oid4vc-dev` wallet with sample PID credentials
- starts the `oid4vc-dev` debugging proxy
- launches Keycloak behind that proxy

Access points:

- Keycloak: `http://localhost:9090`
- Admin Console: `http://localhost:9090/admin`
- Account Console: `http://localhost:9090/realms/wallet-demo/account`
- `oid4vc-dev` dashboard: `http://localhost:9091`
- wallet UI: `http://localhost:8086`

### Sandbox Mode

```bash
scripts/dev.sh
```

Use this mode to test the cross-device flow with real wallets. It:

- builds the extension
- generates a realm config from sandbox certificate material
- starts `ngrok`
- runs Keycloak with a public HTTPS base URL

Sandbox inputs:

| File | Description |
|------|-------------|
| `sandbox-ngrok-combined.pem` | Verifier certificate material used for request-object signing and `x5c` headers |
| `sandbox-verifier-info.json` | Verifier attestation payload for the `verifier_info` claim |

Override the defaults with `--pem`, `--verifier-info`, or `SANDBOX_DIR`.

## Script Options

```text
--local-wallet           Use local oid4vc-dev wallet
--wallet-port <port>     oid4vc-dev wallet port (default: 8086)
--pem <file>             Custom PEM file
--verifier-info <file>   Custom verifier info JSON
--domain <name>          Override ngrok domain
--no-build               Skip Maven build
--skip-realm             Skip realm config generation
--no-proxy               Disable oid4vc-dev proxy
--no-ngrok               Run Keycloak without ngrok
--ngrok-only             Start only the ngrok tunnel
```

## Manual Setup

```bash
mvn package -DskipTests
scripts/setup-local-realm.sh sandbox/sandbox-ngrok-combined.pem sandbox/sandbox-verifier-info.json
```

Then either:

- run `docker compose up` for localhost-only testing, or
- run `scripts/run-keycloak-ngrok.sh --domain <your-ngrok-domain>` for public HTTPS testing.

## Tests

```bash
mvn test
mvn verify
mvn spotless:apply verify
```

`mvn verify` runs the unit tests and writes the unit test coverage report to
`core/target/site/jacoco`. The build enforces a coverage of at least 80%.

The integration tests start a distribution Keycloak and a wallet container. The conformance tests
start a distribution Keycloak and the OpenID conformance suite. Maven skips both by default, and
both run as separate jobs on pull requests:

- `mvn verify -pl integration-tests -am -Pintegration-tests`
- `mvn verify -pl conformance-tests -am -Pconformance-tests`

### Project Layout

- `core`: the extension and its unit tests.
- `integration-tests`: the integration tests, on the official
  [Keycloak Test Framework](https://github.com/keycloak/keycloak/tree/main/test-framework).
- `conformance-tests`: the [OIDF conformance tests](conformance.md).

### Integration Test Setup

- **Keycloak:** The framework runs a local distribution (`kc.test.server=distribution`, configured
  in `.env.test` and the failsafe plugin) and deploys the provider from the `core` module's class
  output (`kc.test.server.hot.deploy=true`).
- **Wallet:** The eudi-dev test wallet runs as a Docker container, and tests receive it through
  `@InjectTestWallet`. A test class declares alternative wallet behaviour with a
  `TestWalletConfig`. The framework replaces the running wallet when a test class requests an
  incompatible configuration.
- **Certificates:** All wallets share one certificate authority seeded by the test setup. The setup
  adds it to the Keycloak truststore, so the server can fetch issuer metadata and status lists over
  HTTPS.
- **Overrides:** `kc.test.wallet.image` and `kc.test.wallet.port` set the wallet image and port.

## Conformance

See [conformance.md](conformance.md).

## Load Testing

Clustered browser+SSE load testing of the cross-device flow: [../loadtest/README.md](../loadtest/README.md).
