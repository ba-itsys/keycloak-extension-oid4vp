#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALM="${LOAD_REALM:-wallet-demo}"
ADMIN_BASE_URI="${LOAD_ADMIN_BASE_URI:-http://host.docker.internal:18080}"
ADMIN_REALM="${LOAD_ADMIN_REALM:-master}"
ADMIN_USERNAME="${LOAD_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${LOAD_ADMIN_PASSWORD:-admin}"
ADMIN_CLIENT_ID="${LOAD_ADMIN_CLIENT_ID:-admin-cli}"

maybe_relax_local_ssl_requirements() {
  if [[ "${ADMIN_BASE_URI}" != http://host.docker.internal:* && "${ADMIN_BASE_URI}" != http://localhost:* ]]; then
    return
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx 'loadtest-keycloak-1-1'; then
    return
  fi

  docker exec loadtest-keycloak-1-1 \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm "${ADMIN_REALM}" \
    --user "${ADMIN_USERNAME}" \
    --password "${ADMIN_PASSWORD}" >/dev/null

  docker exec loadtest-keycloak-1-1 \
    /opt/keycloak/bin/kcadm.sh update realms/"${ADMIN_REALM}" \
    --server http://localhost:8080 \
    -s sslRequired=NONE >/dev/null

  docker exec loadtest-keycloak-1-1 \
    /opt/keycloak/bin/kcadm.sh update realms/"${REALM}" \
    --server http://localhost:8080 \
    -s sslRequired=none >/dev/null
}

maybe_relax_local_ssl_requirements

exec docker run --rm -i \
  -e K6_BROWSER_HEADLESS="${K6_BROWSER_HEADLESS:-true}" \
  -e LOAD_ADMIN_BASE_URI="${ADMIN_BASE_URI}" \
  -e LOAD_BROWSER_BASE_URIS="${LOAD_BROWSER_BASE_URIS:-http://host.docker.internal:18081,http://host.docker.internal:18082}" \
  -e LOAD_WALLET_BASE_URI="${LOAD_WALLET_BASE_URI:-http://host.docker.internal:18085}" \
  -e LOAD_WALLET_INTERNAL_BASE_URI="${LOAD_WALLET_INTERNAL_BASE_URI:-http://oid4vc-dev:8085}" \
  -e LOAD_REALM="${REALM}" \
  -e LOAD_ADMIN_REALM="${ADMIN_REALM}" \
  -e LOAD_ADMIN_USERNAME="${ADMIN_USERNAME}" \
  -e LOAD_ADMIN_PASSWORD="${ADMIN_PASSWORD}" \
  -e LOAD_ADMIN_CLIENT_ID="${ADMIN_CLIENT_ID}" \
  -e LOAD_IDP_ALIAS="${LOAD_IDP_ALIAS:-oid4vp}" \
  -e LOAD_BROWSER_CLIENT_ID="${LOAD_BROWSER_CLIENT_ID:-wallet-mock}" \
  -e LOAD_BROWSER_REDIRECT_URI="${LOAD_BROWSER_REDIRECT_URI:-}" \
  -e LOAD_SD_JWT_VCT="${LOAD_SD_JWT_VCT:-urn:eudi:pid:de:1}" \
  -e LOAD_RATE_PER_SECOND="${LOAD_RATE_PER_SECOND:-10}" \
  -e LOAD_DURATION_SECONDS="${LOAD_DURATION_SECONDS:-30}" \
  -e LOAD_PRE_ALLOCATED_VUS="${LOAD_PRE_ALLOCATED_VUS:-40}" \
  -e LOAD_MAX_VUS="${LOAD_MAX_VUS:-40}" \
  -e LOAD_LOGIN_PAGE_TIMEOUT_MS="${LOAD_LOGIN_PAGE_TIMEOUT_MS:-10000}" \
  -e LOAD_OID4VP_PAGE_TIMEOUT_MS="${LOAD_OID4VP_PAGE_TIMEOUT_MS:-10000}" \
  -e LOAD_POST_WALLET_TIMEOUT_MS="${LOAD_POST_WALLET_TIMEOUT_MS:-20000}" \
  -e LOAD_CALLBACK_TIMEOUT_MS="${LOAD_CALLBACK_TIMEOUT_MS:-20000}" \
  -e LOAD_CONFIGURE_IDP="${LOAD_CONFIGURE_IDP:-true}" \
  -e LOAD_INSECURE_TLS="${LOAD_INSECURE_TLS:-false}" \
  -v "${ROOT_DIR}/loadtest:/loadtest:ro" \
  "${K6_IMAGE:-grafana/k6:master-with-browser}" \
  run /loadtest/oid4vp-cross-device.js
