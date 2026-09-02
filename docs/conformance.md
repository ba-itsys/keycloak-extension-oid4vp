# OIDF Conformance Testing

The `conformance-tests` Maven module runs the OIDF OID4VP verifier test plans against Keycloak
with this extension. It uses the [Keycloak Test Framework](https://github.com/keycloak/keycloak/tree/main/test-framework)
and a locally running [OpenID conformance suite](https://gitlab.com/openid/conformance-suite).
The suite consists of MongoDB, suite server and nginx containers. No public URL, ngrok tunnel or
OIDF account is required.

## Structure

The module mirrors the conformance tests in the Keycloak repository. There is one test class per
conformance module. Each extends `AbstractVerifierConformanceTest` and runs the module as a
parameterized test across every applicable variant combination. `AbstractConformanceTest` holds
the generic run-and-assert logic. The verifier base reconfigures the Keycloak identity provider
per variant and drives the same-device flow.

## Variant Matrix

The tests do not hand-pick variant combinations. The verifier base enumerates the suite's
declared variant dimensions. It asks the suite through `discoverPlanModules` which modules and
module variants apply to each combination. Inapplicable combinations yield nothing. The only
combination excluded up front is the `redirect_uri` client identifier prefix. The provider does
not support it. In practice the suite reduces this to:

- **Final plan** (`oid4vp-1final-verifier-test-plan`, non-HAIP with `vp_profile` `plain_vp`):
  `credential_format` {`sd_jwt_vc`, `iso_mdl`} × `client_id_prefix` {`x509_san_dns`, `x509_hash`}
  × `response_mode` {`direct_post`, `direct_post.jwt`}, with `request_method` `request_uri_signed`.
- **HAIP plan** (`oid4vp-1final-verifier-haip-test-plan`): `credential_format` {`sd_jwt_vc`,
  `iso_mdl`} with `response_mode` `direct_post.jwt` (the plan pins `x509_hash`,
  `request_uri_signed` and the HAIP profile).

The final plan covers the non-HAIP profile including the unencrypted `direct_post`. The HAIP
plan covers the encrypted `direct_post.jwt`. The suite filters out modules that do not apply to a
variant, for example mdoc-only or sd-jwt-only modules.

## Modules

Positive modules assert the verifier accepts a valid presentation. Negative modules assert the
verifier rejects a malformed presentation.

The tests configure the identity provider with `rejectionResponse` set to `error`. A rejected
presentation is then answered with HTTP 4xx. The negative modules read the outcome from the status
and finish `PASSED`. Under the default `redirect` the status is 200 for both outcomes. The modules
then ask for a screenshot of the verification result instead and finish `REVIEW`. The runner fills
that placeholder with a minimal image. Nothing would assert that the presentation was refused.
Positive modules take the screenshot path either way. `ConformanceModuleResult.finishedWith`
accepts their `REVIEW` when evidence was uploaded and no step failed.

The covered modules are
happy-flow, minimal-cnf-jwk, request-uri-method-post, invalid-session-transcript,
invalid-kb-jwt-signature, invalid-credential-signature, invalid-sd-hash, invalid-kb-jwt-nonce,
invalid-kb-jwt-aud, kb-jwt-iat-in-past and kb-jwt-iat-in-future.

## How It Works

- Keycloak runs as a local distribution with TLS. The `hostname` option is set to
  `https://host.testcontainers.internal:8443`. URLs in authorization requests are then
  resolvable from the suite containers.
- For every variant the tests generate verifier signing material and serve an ETSI trust list to
  Keycloak from a local port. They reconfigure the OID4VP identity provider before the module runs.
- Each module is one parameterized JUnit test. The test creates a private plan and starts the
  module. It fetches the same-device wallet link from the Keycloak login page and hands
  `client_id` and `request_uri` to the suite's wallet. It follows the redirects back to Keycloak
  with the browser cookie session. It asserts the module finishes with the expected result.

## Prerequisites

The Keycloak test server runs as a local distribution and binds host port `8443` (TLS). The
suite containers reach it at `host.testcontainers.internal:8443`. Stop any other service on
`8443` first. A manually started OpenID conformance suite publishes `8443` through its nginx.
Shut it down first, otherwise Keycloak cannot start. CI runs in a clean environment.

## Running

The conformance tests are skipped by default. They start the full suite and take long.
Run them with:

```bash
mvn verify -pl conformance-tests -am -Pconformance-tests
```

A single module can be selected with `-Dtest='HappyFlowConformanceTest'`. The suite version is
pinned with the `conformance.suite.imageTag` property in `conformance-tests/pom.xml`. In CI the
conformance and integration tests run as separate parallel jobs on pull requests.
