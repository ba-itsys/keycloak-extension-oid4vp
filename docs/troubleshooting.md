# Troubleshooting

## Missing Docker Environment

The integration and conformance tests need a container runtime. The error "Could not find a valid Docker environment" means one of:

- Docker is not running
- you use a non-default Docker socket
- the socket is not accessible

## Immediate Integration Test Failure

The integration tests bind port 8080 and do not run concurrently.

- Stop whatever holds the port, such as a local Keycloak or a development conformance suite.
- To test the current extension, run `mvn -pl core install -DskipTests` first or use `-am`.

## Stale Extension in Integration Tests

The Keycloak test framework keeps the provider under `/private/tmp/kc-test-framework`, or the equivalent temporary directory, and can serve a stale jar from there. Delete that directory when a test does not see a change.

## Conformance Test Port Conflict

The conformance tests start their own suite and bind host port 8443. Stop any development suite that holds this port.

## Identity Provider Conflict

Keycloak's experimental `oid4vc-vp` feature ships its own OID4VP identity provider and mappers under the same provider ids. See [Step 2 of the Setup Guide](setup.md#step-2-identity-provider).

## Missing Security Events

The event store keeps only the event types enabled in the realm, and Keycloak does not save the identity provider event types by default. See [Storing and Logging Events](events.md#storing-and-logging-events).
