# OIDF Conformance Testing

The `conformance-tests` Maven module runs the OIDF OID4VP verifier test plans against Keycloak
with this extension, using the [Keycloak Test Framework](https://github.com/keycloak/keycloak/tree/main/test-framework)
and a locally running [OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
(MongoDB, suite server and nginx containers). No public URL, ngrok tunnel or OIDF account is
required.

## Structure

The module mirrors the conformance tests in the Keycloak repository: one test class per
conformance module, each extending `AbstractVerifierConformanceTest` and running the module as a
parameterized test across every applicable variant combination. `AbstractConformanceTest` holds
the generic run-and-assert logic. The verifier base reconfigures the Keycloak identity provider
per variant and drives the same-device flow.

## Variant Matrix

The tests do not hand-pick variant combinations. The verifier base enumerates the suite's
declared variant dimensions and asks the suite (via `discoverPlanModules`) which modules and
module variants actually apply to each combination. Inapplicable ones yield nothing. The only
combination excluded up front is the `redirect_uri` client identifier prefix, which the provider
does not support. In practice the suite reduces this to:

- **Final plan** (`oid4vp-1final-verifier-test-plan`, non-HAIP with `vp_profile` `plain_vp`):
  `credential_format` {`sd_jwt_vc`, `iso_mdl`} × `client_id_prefix` {`x509_san_dns`, `x509_hash`}
  × `response_mode` {`direct_post`, `direct_post.jwt`}, with `request_method` `request_uri_signed`.
- **HAIP plan** (`oid4vp-1final-verifier-haip-test-plan`): `credential_format` {`sd_jwt_vc`,
  `iso_mdl`} with `response_mode` `direct_post.jwt` (the plan pins `x509_hash`,
  `request_uri_signed` and the HAIP profile).

The final plan covers the non-HAIP profile including the unencrypted `direct_post`, and the HAIP
plan covers the encrypted `direct_post.jwt`. The suite filters out modules that do not apply to a
variant (for example mdoc-only or sd-jwt-only modules), so the matrix is reduced accordingly.

## Modules

Positive modules assert the verifier accepts a valid presentation. Negative modules assert the
verifier rejects a malformed presentation, which the suite checks by requiring an HTTP 4xx at the
`direct_post` endpoint. Both finish `PASSED`, so there is no error-page screenshot step (that
suite mechanism applies to issuer and OP testing, not verifier testing). The covered modules are
happy-flow, minimal-cnf-jwk, request-uri-method-post, invalid-session-transcript,
invalid-kb-jwt-signature, invalid-credential-signature, invalid-sd-hash, invalid-kb-jwt-nonce,
invalid-kb-jwt-aud, kb-jwt-iat-in-past and kb-jwt-iat-in-future.

## How It Works

- Keycloak runs as a local distribution with TLS, with the `hostname` option set to
  `https://host.testcontainers.internal:8443` so that URLs in authorization requests are
  resolvable from the suite containers.
- For every variant the tests generate verifier signing material, serve an ETSI trust list to
  Keycloak from a local port, and reconfigure the OID4VP identity provider before the module runs.
- Each module is one parameterized JUnit test: it creates a private plan, starts the module,
  fetches the same-device wallet link from the Keycloak login page, hands `client_id` and
  `request_uri` to the suite's wallet, follows the redirects back to Keycloak with the browser
  cookie session, and asserts the module finishes with the expected result.

## Prerequisites

The Keycloak test server runs as a local distribution and binds host port `8443` (TLS) so the
suite containers can reach it at `host.testcontainers.internal:8443`. Stop any other service on
`8443` first. In particular a manually started OpenID conformance suite (its nginx publishes
`8443`) must be shut down, otherwise Keycloak cannot start. CI runs in a clean environment.

## Running

The conformance tests are skipped by default because they start the full suite and take long.
Run them with:

```bash
mvn verify -pl conformance-tests -am -Dconformance.tests.skip=false
```

A single module can be selected with `-Dtest='HappyFlowConformanceTest'`. The suite version is
pinned with the `conformance.suite.imageTag` property in `conformance-tests/pom.xml`. In CI the
conformance and integration tests run as separate parallel jobs on pull requests.
