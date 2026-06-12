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

Typical access points:

- Keycloak: `http://localhost:9090`
- Admin Console: `http://localhost:9090/admin`
- Account Console: `http://localhost:9090/realms/wallet-demo/account`
- `oid4vc-dev` dashboard: `http://localhost:9091`
- wallet UI: `http://localhost:8086`

### Sandbox Mode

```bash
scripts/dev.sh
```

This mode builds the extension, generates a realm config from sandbox certificate material, starts `ngrok`, and runs Keycloak with a public HTTPS base URL suitable for real cross-device wallet tests.

Expected sandbox inputs:

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

## Running Tests

```bash
mvn test
mvn verify
mvn spotless:apply verify
```

- `mvn verify` runs the unit tests. Unit test coverage is reported at `core/target/site/jacoco`
  and must stay at or above 80% (enforced by the build).
- The integration and conformance tests are heavyweight (they start a distribution Keycloak,
  a wallet container, and for conformance the OpenID conformance suite) and are skipped by
  default. Opt in with the `integration-tests` and `conformance-tests` Maven profiles:
  `mvn verify -pl integration-tests -am -Pintegration-tests` and
  `mvn verify -pl conformance-tests -am -Pconformance-tests`. Both run as separate jobs on pull
  requests.

The build is a multi-module Maven project: `core` contains the extension and its unit tests,
`integration-tests` contains the integration tests, built on the official
[Keycloak Test Framework](https://github.com/keycloak/keycloak/tree/main/test-framework).

The framework runs Keycloak as a local distribution (`kc.test.server=distribution`, configured in
`.env.test` and the failsafe plugin) and deploys the provider from the `core` module's class
output (`kc.test.server.hot.deploy=true`). The oid4vc-dev test wallet runs as a Docker container
and is injected into tests with `@InjectTestWallet`. Alternative wallet behaviour is declared with
a `TestWalletConfig`, and the framework replaces the running wallet when a test class requests an
incompatible configuration. All wallets share one certificate authority seeded by the test setup,
which is added to the Keycloak truststore so the server can fetch issuer metadata and status lists
over HTTPS. The wallet image and ports can be overridden with the `kc.test.wallet.image` and
`kc.test.wallet.port` properties.

## Conformance

For OIDF verifier conformance setup and execution, see [conformance.md](conformance.md).

## Load Testing

For clustered browser+SSE load testing of the cross-device flow, see [../loadtest/README.md](../loadtest/README.md).
