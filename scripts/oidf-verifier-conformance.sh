#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUN_DIR=${OID4VP_CONFORMANCE_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oid4vp-verifier-conformance.XXXXXX")}
PROVIDER_JAR="$ROOT_DIR/target/keycloak-extension-oid4vp.jar"
KEYCLOAK_PORT=${OID4VP_CONFORMANCE_KEYCLOAK_PORT:-8080}
SUITE_BASE_URL=${OID4VP_CONFORMANCE_BASE_URL:-${OIDF_CONFORMANCE_BASE_URL:-https://demo.certification.openid.net}}
PUBLIC_BASE_URL=${OID4VP_CONFORMANCE_PUBLIC_BASE_URL:-}
DELETE_PASSING_PLANS=false
KEEP_STACK=false
NO_BUILD=false
NGROK_DOMAIN=${OID4VP_CONFORMANCE_NGROK_DOMAIN:-}
SCENARIO_ARGS=""

usage() {
  cat <<'EOF'
Usage: scripts/oidf-verifier-conformance.sh [options]

Builds the extension, starts Keycloak with a public HTTPS base URL, and runs the
OIDF OID4VP 1.0 Final verifier plans plus the HAIP verifier plan via a standalone
Python driver.

Options:
  --public-base-url <url>    Reuse an existing public HTTPS Keycloak URL and skip ngrok
  --suite-base-url <url>     Override the OIDF suite base URL
  --delete-passing-plans     Delete successful OIDF plans after the run
  --keep-stack               Leave Keycloak running after the script exits
  --no-build                 Skip `mvn package -DskipTests`
  --ngrok-domain <name>      Use a custom ngrok domain
  --run-dir <dir>            Keep logs and reports in the given directory
  --scenario <slug>          Run only the named scenario; may be repeated
  -h, --help                 Show this help

Environment:
  OIDF_CONFORMANCE_API_KEY or OID4VP_CONFORMANCE_API_KEY is required.
  `.env` in the repo root is loaded automatically if present.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --public-base-url)
      PUBLIC_BASE_URL="$2"
      shift 2
      ;;
    --suite-base-url)
      SUITE_BASE_URL="$2"
      shift 2
      ;;
    --delete-passing-plans)
      DELETE_PASSING_PLANS=true
      shift
      ;;
    --keep-stack)
      KEEP_STACK=true
      shift
      ;;
    --no-build)
      NO_BUILD=true
      shift
      ;;
    --ngrok-domain)
      NGROK_DOMAIN="$2"
      shift 2
      ;;
    --run-dir)
      RUN_DIR="$2"
      shift 2
      ;;
    --scenario)
      SCENARIO_ARGS="$SCENARIO_ARGS --scenario $(printf '%s' "$2" | sed "s/'/'\\\\''/g")"
      shift 2
      ;;
    *)
      echo "Unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$RUN_DIR"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

API_KEY=${OID4VP_CONFORMANCE_API_KEY:-${OIDF_CONFORMANCE_API_KEY:-}}
if [ -z "$API_KEY" ]; then
  echo "error: set OID4VP_CONFORMANCE_API_KEY or OIDF_CONFORMANCE_API_KEY" >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

require_cmd python3
require_cmd curl
require_cmd docker
require_cmd openssl

if [ "$NO_BUILD" != "true" ]; then
  echo "Building extension..."
  (cd "$ROOT_DIR" && mvn -q -DskipTests package)
else
  if [ ! -f "$PROVIDER_JAR" ]; then
    echo "error: packaged provider jar not found at $PROVIDER_JAR" >&2
    exit 1
  fi
fi

if [ -z "$PUBLIC_BASE_URL" ]; then
  require_cmd ngrok
fi

NGROK_LOG="$RUN_DIR/ngrok.log"
COMPOSE_OVERRIDE="$RUN_DIR/docker-compose.oidf.yml"
COMPOSE_FILES="-f $ROOT_DIR/docker-compose.yml -f $COMPOSE_OVERRIDE"

cleanup() {
  if [ -n "${NGROK_PID:-}" ] && kill -0 "$NGROK_PID" 2>/dev/null; then
    kill "$NGROK_PID" 2>/dev/null || true
    wait "$NGROK_PID" 2>/dev/null || true
  fi
  if [ "$KEEP_STACK" != "true" ]; then
    docker compose $COMPOSE_FILES down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

get_public_url() {
  for api_port in 4040 4041 4042 4043 4044 4045; do
    json=$(curl -fsS "http://127.0.0.1:${api_port}/api/tunnels" 2>/dev/null || true)
    if [ -z "$json" ]; then
      continue
    fi
    url=$(python3 - <<'PY' "$KEYCLOAK_PORT" "$json"
import json
import sys

port = ":" + sys.argv[1]
payload = json.loads(sys.argv[2])
for tunnel in payload.get("tunnels", []):
    public_url = tunnel.get("public_url", "")
    addr = str(tunnel.get("config", {}).get("addr", ""))
    if public_url.startswith("https://") and (addr.endswith(port) or ("localhost" + port) in addr):
        print(public_url)
        raise SystemExit(0)
raise SystemExit(1)
PY
    ) || true
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
  done
  return 1
}

if [ -z "$PUBLIC_BASE_URL" ]; then
  echo "Starting ngrok..."
  NGROK_ARGS="http $KEYCLOAK_PORT --log=stdout --log-format=json"
  if [ -n "$NGROK_DOMAIN" ]; then
    NGROK_ARGS="$NGROK_ARGS --url=$NGROK_DOMAIN"
  fi
  # shellcheck disable=SC2086
  ngrok $NGROK_ARGS >"$NGROK_LOG" 2>&1 &
  NGROK_PID=$!

  attempt=0
  until PUBLIC_BASE_URL=$(get_public_url || true); [ -n "$PUBLIC_BASE_URL" ]; do
    attempt=$((attempt + 1))
    if ! kill -0 "$NGROK_PID" 2>/dev/null; then
      echo "error: ngrok exited early" >&2
      cat "$NGROK_LOG" >&2 || true
      exit 1
    fi
    if [ "$attempt" -ge 120 ]; then
      echo "error: timed out waiting for ngrok public URL" >&2
      exit 1
    fi
    sleep 0.25
  done
fi

cat >"$COMPOSE_OVERRIDE" <<EOF
services:
  keycloak:
    environment:
      KC_HOSTNAME: "$PUBLIC_BASE_URL"
      KC_PROXY_HEADERS: xforwarded
    extra_hosts:
      - "host.docker.internal:host-gateway"
EOF

echo "Starting Keycloak..."
docker compose $COMPOSE_FILES up -d keycloak >/dev/null

attempt=0
until curl -fsS "http://127.0.0.1:${KEYCLOAK_PORT}/realms/wallet-demo" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 180 ]; then
    echo "error: Keycloak did not become ready in time" >&2
    docker compose $COMPOSE_FILES logs keycloak >&2 || true
    exit 1
  fi
  sleep 1
done

REPORT_JSON="$RUN_DIR/report.json"

echo "Running OIDF verifier conformance..."
DELETE_ARGS=""
if [ "$DELETE_PASSING_PLANS" = "true" ]; then
  DELETE_ARGS="--delete-passing-plans"
fi
# shellcheck disable=SC2086
OID4VP_CONFORMANCE_API_KEY="$API_KEY" \
OID4VP_CONFORMANCE_BASE_URL="$SUITE_BASE_URL" \
python3 "$ROOT_DIR/scripts/oidf_verifier_conformance.py" \
  --work-dir "$RUN_DIR" \
  --local-base-url "http://127.0.0.1:${KEYCLOAK_PORT}" \
  --public-base-url "$PUBLIC_BASE_URL" \
  --report-json "$REPORT_JSON" \
  $DELETE_ARGS \
  $SCENARIO_ARGS

echo "Run directory: $RUN_DIR"
echo "Report JSON:   $REPORT_JSON"
if [ -n "${NGROK_PID:-}" ]; then
  echo "ngrok log:     $NGROK_LOG"
fi
