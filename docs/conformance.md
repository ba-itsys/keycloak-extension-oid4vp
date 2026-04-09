# OIDF Conformance Testing

This repo includes an integration test that drives the OpenID Foundation verifier conformance suite against the Keycloak OID4VP verifier flow.

## What it covers

`KeycloakOid4vpConformanceIT` runs the current same-device verifier module for this matrix:
- `sd_jwt_vc` + `x509_san_dns` + `direct_post.jwt`
- `sd_jwt_vc` + `x509_hash` + `direct_post.jwt`
- `iso_mdl` + `x509_san_dns` + `direct_post.jwt`
- `iso_mdl` + `x509_hash` + `direct_post.jwt`

The test creates a fresh signing keypair, publishes a minimal ETSI trust list containing the necessary issuer certificates for each scenario, creates an OIDF plan, starts one module, and then triggers our verifier through Keycloak.

## Configuration

The test reads environment variables first and then `.env` from the repo root. It is skipped when the API key is absent. In CI it is also skipped by default unless `OID4VP_CONFORMANCE_RUN_IN_CI=true`.

Supported keys:
- `OIDF_CONFORMANCE_API_KEY` or `OID4VP_CONFORMANCE_API_KEY`: required OIDF token
- `OIDF_CONFORMANCE_BASE_URL` or `OID4VP_CONFORMANCE_BASE_URL`: optional, defaults to `https://demo.certification.openid.net`
- `OID4VP_CONFORMANCE_PLAN_NAME`: optional, defaults to `oid4vp-1final-verifier-test-plan`
- `OID4VP_CONFORMANCE_TEST_MODULE`: optional explicit module name; otherwise the first module from the plan is used
- `OID4VP_CONFORMANCE_PUBLIC_BASE_URL`: optional public HTTPS URL for the local Keycloak instance
- `OID4VP_CONFORMANCE_KEEP_PLANS_ON_SUCCESS`: optional, defaults to `true`; set `false` only if you explicitly want the test to delete successful plans afterwards
- `OID4VP_CONFORMANCE_RUN_IN_CI`: optional, defaults to `false`

If `OID4VP_CONFORMANCE_PUBLIC_BASE_URL` is not set, the test falls back to a local `ngrok` binary on `PATH`.
The test probes the local ngrok admin API on ports `4040` through `4045`, because ngrok may shift the admin port when `4040` is already in use.

## Running

Build the provider first so the Keycloak test container can mount the current jar:

```bash
mvn -q -DskipTests package
mvn -q -Dit.test=KeycloakOid4vpConformanceIT failsafe:integration-test
```

## Notes

- The conformance suite needs a public verifier URL because it fetches our `request_uri` and POSTs to our `response_uri`.
- Successful runs are kept in the OIDF UI by default so their logs and result pages remain inspectable after the test completes.
- All conformance scenarios run with `direct_post.jwt`.
- The `x509_hash` scenarios use `enforceHaip=true`, which overrides the effective `clientIdScheme` to `x509_hash`.
- The `x509_san_dns` scenarios keep `enforceHaip=false` and configure `responseMode=direct_post.jwt` explicitly.
- Each scenario uses a fresh Keycloak IdP alias so mapper and verifier config changes cannot leak across runs.
- The Keycloak login page renders the normal `openid4vp://` same-device deep link. The test reuses the `client_id` and `request_uri` from that link and sends them to the OIDF module's HTTPS `authorization_endpoint`.
- Before calling the OIDF module, the test fetches the local request object and asserts that `client_id` and DCQL match the scenario. This catches stale local config before a suite failure hides the root cause.
- In multi-node deployments, conformance callbacks and cross-device completion require a shared Keycloak single-use object store; each node serves only its local SSE connections, and each open watcher polls completion state from that shared store on a virtual thread.
- If the OIDF demo suite renames plans or modules again, override `OID4VP_CONFORMANCE_PLAN_NAME` and optionally `OID4VP_CONFORMANCE_TEST_MODULE` instead of changing test code first.
