# Load Testing

This directory contains a k6 browser loadtest setup for the OID4VP cross-device flow.

The loadtest uses:

- a real Chromium page for the Keycloak login browser path
- the page's own `EventSource` handling for cross-device completion
- the local `oid4vc-dev` wallet mock to submit the presentation
- a two-node Keycloak cluster with shared database and shared cache discovery

## Scope

The goal is to exercise the real browser-side SSE flow under load, not just the raw HTTP endpoints.

What it covers:

- real OID4VP login pages
- real browser-side SSE handling on `/cross-device/status`
- real wallet request-object fetch and `direct_post` callback
- clustered Keycloak nodes behind HAProxy
- transient-user logins, so repeated concurrent runs do not need persistent brokered users

What it does not cover:

- hardware wallet latency or real mobile deep links
- a distributed load-generator farm
- deterministic node pinning of the wallet callback

## Files

- [oid4vp-cross-device.js](/Users/dominik/projects/keycloak-extension-oid4vp/loadtest/oid4vp-cross-device.js)
  k6 browser scenario
- [run-k6-browser.sh](/Users/dominik/projects/keycloak-extension-oid4vp/loadtest/run-k6-browser.sh)
  wrapper around the browser-enabled k6 image
- [docker-compose.cluster.yml](/Users/dominik/projects/keycloak-extension-oid4vp/loadtest/docker-compose.cluster.yml)
  local two-node Keycloak cluster plus mock wallet
- [haproxy.cfg](/Users/dominik/projects/keycloak-extension-oid4vp/loadtest/haproxy.cfg)
  front door for the local cluster

## Local Cluster

Build the provider jar first:

```bash
mvn package -DskipTests
```

Start the clustered stack:

```bash
docker compose -f loadtest/docker-compose.cluster.yml up -d
```

Default ports:

- HAProxy: `18080`
- Keycloak node 1: `18081`
- Keycloak node 2: `18082`
- mock wallet API: `18085`
- mock wallet UI: `18086`

Wait until the realm is reachable:

```bash
until curl -fsS http://localhost:18080/realms/wallet-demo/.well-known/openid-configuration >/dev/null; do sleep 2; done
```

## Running The Loadtest

The wrapper uses Docker and the browser-enabled k6 image, so you do not need a local k6 install.

Default local run:

```bash
./loadtest/run-k6-browser.sh
```

Example higher-rate run:

```bash
LOAD_RATE_PER_SECOND=30 \
LOAD_DURATION_SECONDS=30 \
LOAD_PRE_ALLOCATED_VUS=40 \
LOAD_MAX_VUS=40 \
./loadtest/run-k6-browser.sh
```

Example front-door-only run through HAProxy:

```bash
LOAD_BROWSER_BASE_URIS=http://host.docker.internal:18080 \
./loadtest/run-k6-browser.sh
```

Example alternate-port run:

```bash
HAPROXY_PORT=18180 KC1_PORT=18181 KC2_PORT=18182 WALLET_PORT=18185 WALLET_UI_PORT=18186 \
docker compose -f loadtest/docker-compose.cluster.yml up -d

LOAD_ADMIN_BASE_URI=http://host.docker.internal:18180 \
LOAD_BROWSER_BASE_URIS=http://host.docker.internal:18181,http://host.docker.internal:18182 \
LOAD_WALLET_BASE_URI=http://host.docker.internal:18185 \
./loadtest/run-k6-browser.sh
```

## What The Script Configures

During `setup()`, the k6 script updates the OID4VP IdP to keep the loadtest predictable:

- enables transient users via `doNotStoreUsers=true`
- disables same-device and keeps cross-device enabled
- uses `clientIdScheme=plain`
- keeps `responseMode=direct_post.jwt`
- reduces DCQL to one SD-JWT PID credential
- points `trustListUrl` at the local `oid4vc-dev` wallet container

That avoids first-login persistence races and keeps the measured path focused on the browser SSE flow.

## Important Environment Variables

- `LOAD_ADMIN_BASE_URI`
  Base URI used for Keycloak admin setup. Default: `http://host.docker.internal:18080`
- `LOAD_BROWSER_BASE_URIS`
  Comma-separated browser target URIs. Default: `http://host.docker.internal:18081,http://host.docker.internal:18082`
- `LOAD_WALLET_BASE_URI`
  Browser-side load generator access to the mock wallet API. Default: `http://host.docker.internal:18085`
- `LOAD_WALLET_INTERNAL_BASE_URI`
  Wallet base URI that Keycloak nodes use inside the compose network. Default: `http://oid4vc-dev:8085`
- `LOAD_REALM`
  Default: `wallet-demo`
- `LOAD_IDP_ALIAS`
  Default: `oid4vp`
- `LOAD_BROWSER_CLIENT_ID`
  Default: `wallet-mock`
- `LOAD_BROWSER_REDIRECT_URI`
  Optional fixed redirect URI. Default: browser target base URI + `/wallet-mock/callback`
- `LOAD_SD_JWT_VCT`
  Default: `urn:eudi:pid:de:1`
- `LOAD_RATE_PER_SECOND`
  Default: `10`
- `LOAD_DURATION_SECONDS`
  Default: `30`
- `LOAD_PRE_ALLOCATED_VUS`
  Default: `40`
- `LOAD_MAX_VUS`
  Default: `40`
- `LOAD_CONFIGURE_IDP`
  Default: `true`
- `LOAD_INSECURE_TLS`
  Default: `false`
- `LOAD_QR_SCAN_DELAY_MS`
  Delay between QR visibility and wallet submission. Default: `750`
- `LOAD_WALLET_APPROVAL_DELAY_MS`
  Simulated user review delay before wallet approval. Default: `500`
- `LOAD_POST_APPROVAL_BROWSER_DELAY_MS`
  Delay before the browser starts checking for completion after wallet approval. Default: `250`
- `LOAD_FIRST_BROKER_SUBMIT_DELAY_MS`
  Delay before submitting the first-broker-login form. Default: `400`

## Routing Notes

There are two useful local modes:

- explicit-node browser traffic
  `LOAD_BROWSER_BASE_URIS=http://host.docker.internal:18081,http://host.docker.internal:18082`
- front-door-only browser traffic
  `LOAD_BROWSER_BASE_URIS=http://host.docker.internal:18080`

For this OID4VP flow, the wallet callback target is embedded in the generated request object. That means deterministic browser-on-node-1 plus wallet-callback-on-node-2 forcing is not currently available from the outside. The HAProxy mode is still useful because reconnects and callbacks can land on different nodes through the shared front door.
