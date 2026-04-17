# OIDF Conformance Testing

This repo runs verifier conformance outside the Java test suite.

- [`scripts/oidf-verifier-conformance.sh`](/Users/dominik/projects/keycloak-extension-oid4vp/scripts/oidf-verifier-conformance.sh) builds the provider, starts Keycloak, opens a public HTTPS URL, and then invokes the Python driver.
- [`scripts/oidf_verifier_conformance.py`](/Users/dominik/projects/keycloak-extension-oid4vp/scripts/oidf_verifier_conformance.py) configures Keycloak for each scenario, creates private OIDF plans, runs every module in each plan, and writes a JSON report.

## Why Not The Official Python Runner

The official suite still ships `scripts/run-test-plan.py`, and the OpenID Foundation recommends it for CI in general. After reviewing the current upstream runner, this repo does not use it directly for verifier testing:

- the upstream runner only auto-drives `WAITING` modules through `op_test` recursion or bundled sample clients
- it does not contain a verifier-specific hook that can launch an external OID4VP verifier flow from a module's exported `authorization_endpoint`
- verifier testing here still needs custom logic to:
  - reconfigure the Keycloak IdP per scenario
  - fetch the same-device `openid4vp://` link from the Keycloak login page
  - forward `client_id` and `request_uri` into the suite's mock-wallet endpoint
  - keep or delete private OIDF plans based on the local result

So this repo uses the suite HTTP API directly instead of wrapping `run-test-plan.py`.

## Covered Matrix

The standalone runner executes every module in each of these supported verifier scenarios:

- OID4VP Final: `sd_jwt_vc` + `x509_san_dns` + `direct_post.jwt`
- OID4VP Final: `sd_jwt_vc` + `x509_hash` + `direct_post.jwt`
- OID4VP Final: `iso_mdl` + `x509_san_dns` + `direct_post.jwt`
- OID4VP Final: `iso_mdl` + `x509_hash` + `direct_post.jwt`
- OID4VP Final/HAIP: `sd_jwt_vc` + `x509_hash` + `direct_post.jwt`
- OID4VP Final/HAIP: `iso_mdl` + `x509_hash` + `direct_post.jwt`

For each scenario the runner:

- generates fresh verifier signing material
- serves a temporary ETSI trust-list JWT to Keycloak
- creates a fresh Keycloak IdP alias and mapper set
- creates a private OIDF plan
- runs every module returned by that plan
- prints plan URLs and writes a JSON report with per-module status

## Configuration

The wrapper loads environment variables first and then `.env` from the repo root.

Required:

- `OIDF_CONFORMANCE_API_KEY` or `OID4VP_CONFORMANCE_API_KEY`

Optional:

- `OIDF_CONFORMANCE_BASE_URL` or `OID4VP_CONFORMANCE_BASE_URL`
  Default: `https://demo.certification.openid.net`
- `OID4VP_CONFORMANCE_PUBLIC_BASE_URL`
  Reuse an existing public HTTPS Keycloak URL and skip ngrok
- `OID4VP_CONFORMANCE_NGROK_DOMAIN`
  Use a custom ngrok domain when the wrapper starts ngrok
- `OID4VP_CONFORMANCE_RUN_DIR`
  Keep logs and reports in a chosen directory instead of a temp dir

## Running

```bash
scripts/oidf-verifier-conformance.sh
```

Useful options:

- `--public-base-url <url>`: skip ngrok and reuse an existing public Keycloak URL
- `--suite-base-url <url>`: point at staging or another suite instance
- `--delete-passing-plans`: delete successful private OIDF plans after the run
- `--keep-stack`: leave Keycloak running after the script exits
- `--no-build`: skip `mvn package -DskipTests`

## Plan Retention

By default the runner keeps every OIDF plan on the website.

Nothing is deleted unless you explicitly opt in with:

```bash
scripts/oidf-verifier-conformance.sh --delete-passing-plans
```

Even with that flag, failed scenarios keep their plans for inspection.

## Notes

- The suite needs a public verifier URL because it fetches `request_uri` and POSTs to `response_uri`.
- The Keycloak login page still renders the normal same-device deep link. The runner reuses the generated `client_id` and `request_uri` and sends them to the suite's exported `authorization_endpoint`.
- Before each module call, the runner fetches the local request object and checks the effective `client_id` and DCQL shape so stale local config fails fast.
- The trust-list JWT is intentionally served without signature verification; this is acceptable for this local conformance harness because the verifier config does not set a trust-list signing certificate.
