# Contributing to keycloak-extension-oid4vp

This repository contains a Keycloak identity provider extension for OID4VP wallet login. This guide covers the local setup that actually exists in this repo, the checks to run, and the documentation to update when behavior changes.

## Getting Started

1. Create a feature branch.
2. Make the code and test changes.
3. Run formatting and verification locally.
4. Update docs when configuration, scripts, or behavior changed.
5. Commit with a conventional commit message and `Signed-off-by`.

## Prerequisites

- Java 21
- Maven 3.9+
- Docker
- `ngrok` for public-wallet or conformance flows
- `oid4vc-dev` if you want the local wallet/proxy workflow from `scripts/dev.sh --local-wallet`

## Local Development

For the fastest local setup, use:

```bash
scripts/dev.sh --local-wallet
```

That script builds the provider, regenerates the local realm import, starts the optional local wallet, and launches Keycloak with the provider mounted.

If you prefer the manual path:

```bash
mvn -DskipTests package
scripts/setup-local-realm.sh sandbox/sandbox-ngrok-combined.pem sandbox/sandbox-verifier-info.json
docker compose up
```

Important local files:

- Provider code: `src/main/java/...`
- Tests: `src/test/java/...`
- Demo realm import used by Docker: `src/test/resources/realm-wallet-demo-local.json`
- Local helper scripts: `scripts/dev.sh`, `scripts/setup-local-realm.sh`, `scripts/run-keycloak-ngrok.sh`

## Checks

Run the same checks expected for a normal change:

```bash
mvn spotless:apply
mvn verify
```

Useful narrower commands while iterating:

```bash
mvn test
mvn -Dit.test='*E2eIT,*ConformanceIT' failsafe:integration-test
```

The live conformance test is opt-in and requires credentials. See `docs/conformance.md` for the environment variables and ngrok/public URL requirements.

## Code Expectations

- Keep changes focused and avoid broad refactors without a concrete payoff.
- Add or update tests for behavior changes.
- Prefer simplifying test harnesses and helper APIs when they start accumulating special cases.
- Do not commit local sandbox material, `.env`, or generated secrets.

## Documentation Expectations

Update the relevant docs when you change:

- user-facing configuration in `README.md`
- request/verification behavior in `docs/request-flow.md`
- conformance setup or assumptions in `docs/conformance.md`
- local scripts or development workflow in `README.md` or this file

## Commit Messages

Use Conventional Commits and include a DCO signoff:

```text
fix(conformance): isolate idp config per scenario

Signed-off-by: Jane Smith <jane.smith@example.com>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`.

## Pull Requests

Before opening a PR, make sure:

- `mvn verify` passes locally
- formatting is applied
- docs are updated where needed
- the change description explains any spec or Keycloak behavior impact

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
