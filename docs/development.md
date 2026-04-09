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
mvn -Pcoverage verify
mvn spotless:apply verify
```

- `mvn verify` runs the full suite, including conformance tests.
- `mvn -Pcoverage verify` generates JaCoCo coverage for unit tests and E2E tests, but excludes the conformance suite from the coverage run.

## Conformance

For OIDF verifier conformance setup and execution, see [conformance.md](conformance.md).

## Load Testing

For clustered browser+SSE load testing of the cross-device flow, see [../loadtest/README.md](../loadtest/README.md).
