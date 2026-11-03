# OIDF Conformance Testing

The `conformance-tests` Maven module runs the OIDF OID4VP verifier test plans against Keycloak
with this extension, using the [Keycloak Test Framework](https://github.com/keycloak/keycloak/tree/main/test-framework)
and a local [OpenID conformance suite](https://gitlab.com/openid/conformance-suite) (MongoDB,
suite server and nginx containers). The tests need no public URL, ngrok tunnel or OIDF account.

## Structure

The module mirrors the conformance tests in the Keycloak repository, with one test class per
conformance module.

- `AbstractConformanceTest` holds the generic logic for running a module and asserting its result.
- `AbstractVerifierConformanceTest` reconfigures the Keycloak identity provider per variant and
  drives the same-device flow. Each test class extends it and runs its module as a parameterized
  test across every applicable variant combination.

## Variant Matrix

The verifier base enumerates the variant dimensions the suite declares and asks the suite through
`discoverPlanModules` which modules and module variants apply. A combination that does not apply
yields nothing. The tests leave out only the `redirect_uri` client identifier prefix up front,
because the provider does not support it. The suite also filters out modules that do not apply to
a variant, for example mdoc-only or sd-jwt-only modules. In practice this leaves two plans:

- **Final plan** (`oid4vp-1final-verifier-test-plan`, non-HAIP with `vp_profile` `plain_vp`,
  including the unencrypted `direct_post`):
  `credential_format` {`sd_jwt_vc`, `iso_mdl`} × `client_id_prefix` {`x509_san_dns`, `x509_hash`}
  × `response_mode` {`direct_post`, `direct_post.jwt`}, with `request_method` `request_uri_signed`.
- **HAIP plan** (`oid4vp-1final-verifier-haip-test-plan`): `credential_format` {`sd_jwt_vc`,
  `iso_mdl`} with `response_mode` `direct_post.jwt` (the plan pins `x509_hash`,
  `request_uri_signed` and the HAIP profile).

## Modules

Positive modules assert that the verifier accepts a valid presentation. Negative modules assert
that it rejects a malformed presentation. Each negative module runs twice, once per value of
`rejectionResponse`:

| `rejectionResponse` | Keycloak's answer | Module result |
|---------------------|-------------------|---------------|
| `error` | HTTP 4xx | The module reads the outcome from the status and finishes `PASSED`. |
| `redirect` (default) | HTTP 200 for both outcomes | The module asks for a screenshot of the verification result and finishes `REVIEW`. The runner fills that placeholder with a minimal image. This run does not assert that the presentation was refused. |

Positive modules take the screenshot path under either setting.
`ConformanceModuleResult.finishedWith` accepts a `REVIEW` result when evidence was uploaded and no
step failed.

Covered modules: happy-flow, minimal-cnf-jwk, request-uri-method-post, invalid-session-transcript,
invalid-kb-jwt-signature, invalid-credential-signature, invalid-sd-hash, invalid-kb-jwt-nonce,
invalid-kb-jwt-aud, kb-jwt-iat-in-past and kb-jwt-iat-in-future.

## Test Flow

1. Keycloak runs as a local distribution with TLS. The `hostname` option is
   `https://host.testcontainers.internal:8443`, so the suite containers can resolve the URLs in
   authorization requests.
2. For every variant, the tests generate verifier signing material, serve an ETSI trust list to
   Keycloak from a local port, and reconfigure the OID4VP identity provider.
3. The parameterized JUnit test creates a private plan and starts the module.
4. The test fetches the same-device wallet link from the Keycloak login page and hands `client_id`
   and `request_uri` to the suite's wallet.
5. The test follows the redirects back to Keycloak with the browser cookie session and asserts
   that the module finishes with the expected result.

## Prerequisites

The Keycloak test server binds host port `8443` (TLS), and the suite containers reach it at
`host.testcontainers.internal:8443`. Stop any other service on `8443` before a run. A manually
started OpenID conformance suite publishes `8443` through its nginx, and Keycloak cannot start
until you shut that suite down. CI needs no such step.

## Test Execution

Maven skips these tests by default, because they start the full suite and take a long time.

```bash
mvn verify -pl conformance-tests -am -Pconformance-tests
```

- **Single module:** Add `-Dtest='HappyFlowConformanceTest'`.
- **Suite version:** The `conformance.suite.imageTag` property in `conformance-tests/pom.xml` pins it.
- **CI:** The conformance and integration tests run as separate parallel jobs on pull requests.
