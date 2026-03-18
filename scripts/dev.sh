#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PROVIDER_JAR="$ROOT_DIR/target/keycloak-extension-oid4vp.jar"

# Sensible defaults – override via flags or env vars
DEFAULT_SANDBOX_DIR="${SANDBOX_DIR:-${ROOT_DIR}/sandbox}"
DEFAULT_PEM_FILE="${DEFAULT_SANDBOX_DIR}/sandbox-ngrok-combined.pem"
DEFAULT_VERIFIER_INFO="${DEFAULT_SANDBOX_DIR}/sandbox-verifier-info.json"

usage() {
  cat <<'EOF'
Usage: scripts/dev.sh [options]

One-command local development: builds the extension, generates realm config
from sandbox certificates, and starts Keycloak (optionally behind an ngrok tunnel).

Modes:
  (default)                Sandbox mode – uses X.509 sandbox certificates
  --local-wallet           Use local oid4vc-dev wallet (trust list from wallet, no ngrok)

Options:
  --pem <file>             Combined PEM file (cert chain + private key)
                           Default: sandbox/sandbox-ngrok-combined.pem
  --verifier-info <file>   Verifier attestation JSON file
                           Default: sandbox/sandbox-verifier-info.json
  --domain <name>          Custom ngrok domain (overrides auto-detection)
                           Default: extracted from SAN DNS in PEM cert, or none
  --no-build               Skip Maven build (use existing packaged provider jar)
  --skip-realm             Skip realm generation (use existing local realm)
  --no-proxy               Disable oid4vc-dev proxy even if available
  --no-ngrok               Run Keycloak without ngrok (localhost only)
  --ngrok-only             Start only ngrok tunnel, no Keycloak
  --wallet-port <port>     oid4vc-dev wallet port (default: 8086, only with --local-wallet)
  -h, --help               Show this help

Environment variables (override defaults):
  SANDBOX_DIR              Base directory for sandbox certs
                           Default: sandbox/

Examples:
  scripts/dev.sh                                       # Everything with defaults
  scripts/dev.sh --local-wallet                        # Use oid4vc-dev wallet
  scripts/dev.sh --local-wallet --no-build             # Wallet mode, skip rebuild
  scripts/dev.sh --no-ngrok                            # Local only, no tunnel
  scripts/dev.sh --no-build                            # Skip rebuild
  scripts/dev.sh --pem /tmp/my.pem --domain foo.ngrok-free.app
  SANDBOX_DIR=/opt/certs scripts/dev.sh                # Custom cert location
EOF
}

PEM_FILE="$DEFAULT_PEM_FILE"
VERIFIER_INFO="$DEFAULT_VERIFIER_INFO"
NGROK_DOMAIN=""
DOMAIN_EXPLICIT=false
DO_BUILD=true
DO_REALM=true
DO_PROXY=true
DO_NGROK=true
NGROK_ONLY=false
LOCAL_WALLET=false
WALLET_PORT=8086

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --local-wallet) LOCAL_WALLET=true; shift ;;
    --wallet-port) WALLET_PORT="$2"; shift 2 ;;
    --pem)         PEM_FILE="$2"; shift 2 ;;
    --verifier-info) VERIFIER_INFO="$2"; shift 2 ;;
    --domain)      NGROK_DOMAIN="$2"; DOMAIN_EXPLICIT=true; shift 2 ;;
    --no-build)    DO_BUILD=false; shift ;;
    --skip-realm)  DO_REALM=false; shift ;;
    --no-proxy)    DO_PROXY=false; shift ;;
    --no-ngrok)    DO_NGROK=false; shift ;;
    --ngrok-only)  NGROK_ONLY=true; shift ;;
    *)             echo "Unexpected argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# Local wallet mode implies no-ngrok (localhost only)
if [ "$LOCAL_WALLET" = "true" ]; then
  DO_NGROK=false
  if ! command -v oid4vc-dev >/dev/null 2>&1; then
    echo "Error: --local-wallet requires oid4vc-dev on PATH" >&2
    echo "Install from: https://github.com/dominikschlosser/oid4vc-dev" >&2
    exit 1
  fi
fi

# Step 1: Build
if [ "$DO_BUILD" = "true" ]; then
  echo "==> Building extension..."
  (cd "$ROOT_DIR" && mvn package -DskipTests -q)
  echo "    Build complete."
else
  if [ ! -f "$PROVIDER_JAR" ]; then
    echo "Packaged provider jar not found at target/keycloak-extension-oid4vp.jar. Run without --no-build or build manually." >&2
    exit 1
  fi
  echo "==> Skipping build (--no-build)"
fi

# Step 2: Generate realm config
if [ "$DO_REALM" = "true" ]; then
  echo "==> Generating local realm config..."
  if [ ! -f "$PEM_FILE" ]; then
    echo "PEM file not found: $PEM_FILE" >&2
    echo "Set --pem or SANDBOX_DIR to point to your sandbox certificates." >&2
    exit 1
  fi
  if [ ! -f "$VERIFIER_INFO" ]; then
    echo "Verifier info not found: $VERIFIER_INFO" >&2
    echo "Set --verifier-info or SANDBOX_DIR to point to your sandbox certificates." >&2
    exit 1
  fi
  TRUST_LIST_ARGS=""
  if [ "$LOCAL_WALLET" = "true" ]; then
    TRUST_LIST_ARGS="http://host.docker.internal:$WALLET_PORT/api/trustlist"
  fi
  "$ROOT_DIR/scripts/setup-local-realm.sh" "$PEM_FILE" "$VERIFIER_INFO" $TRUST_LIST_ARGS
else
  echo "==> Skipping realm generation (--skip-realm)"
fi

# Extract ngrok domain from cert SAN if not explicitly set
if [ "$DO_NGROK" = "true" ] && [ "$DOMAIN_EXPLICIT" = "false" ] && [ -f "$PEM_FILE" ] && command -v openssl >/dev/null 2>&1; then
  SAN_DNS="$(openssl x509 -in "$PEM_FILE" -noout -ext subjectAltName 2>/dev/null \
    | grep -o 'DNS:[^ ,]*' | head -n1 | cut -d: -f2 || true)"
  if [ -n "$SAN_DNS" ]; then
    NGROK_DOMAIN="$SAN_DNS"
    echo "==> Detected ngrok domain from certificate SAN: $NGROK_DOMAIN"
  fi
fi

# Step 3: Prepare oid4vc-dev proxy wrapper (runs Keycloak as subprocess)
PROXY_PORT=9090
KC_PORT=8080

# KC_WRAPPER is prepended to the docker compose command so the proxy can
# capture Keycloak's stdout (enc keys, credentials) for its dashboard.
if [ "$DO_PROXY" = "true" ] && command -v oid4vc-dev >/dev/null 2>&1; then
  echo "==> oid4vc-dev proxy will wrap Keycloak (port $PROXY_PORT -> $KC_PORT)"
  echo "    oid4vc-dev dashboard: http://localhost:9091"
  export KC_WRAPPER="oid4vc-dev proxy --target http://localhost:$KC_PORT --port $PROXY_PORT --"
  export NGROK_TARGET_PORT="$PROXY_PORT"
elif [ "$DO_PROXY" = "true" ]; then
  echo "==> oid4vc-dev not found, skipping proxy"
fi

# Step 4: Start oid4vc-dev wallet (if --local-wallet)
WALLET_PID=""
if [ "$LOCAL_WALLET" = "true" ]; then
  echo "==> Starting oid4vc-dev wallet on port $WALLET_PORT..."
  oid4vc-dev wallet serve --pid --port "$WALLET_PORT" --register &
  WALLET_PID=$!
  # Give the wallet a moment to start
  sleep 1
  echo "    Wallet UI: http://localhost:$WALLET_PORT"
  echo "    Trust list: http://localhost:$WALLET_PORT/api/trustlist"
fi

PROXY_OVERRIDE=""
cleanup() {
  if [ -n "$WALLET_PID" ] && kill -0 "$WALLET_PID" 2>/dev/null; then
    echo "==> Stopping oid4vc-dev wallet..."
    kill "$WALLET_PID" 2>/dev/null || true
  fi
  if [ -n "$PROXY_OVERRIDE" ]; then
    rm -f "$PROXY_OVERRIDE" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Step 5: Start Keycloak (with or without ngrok)
if [ "$DO_NGROK" = "false" ]; then
  echo "==> Starting Keycloak (localhost only)..."
  cd "$ROOT_DIR"
  EXTERNAL_PORT="${NGROK_TARGET_PORT:-$KC_PORT}"
  COMPOSE_FILES="-f docker-compose.yml"
  # When proxy is active, tell Keycloak its external hostname (same as ngrok path does)
  if [ -n "${KC_WRAPPER:-}" ]; then
    PROXY_OVERRIDE="$ROOT_DIR/docker-compose.proxy.yml"
    cat > "$PROXY_OVERRIDE" <<YAML
services:
  keycloak:
    environment:
      KC_HOSTNAME: "http://localhost:$EXTERNAL_PORT"
      KC_PROXY_HEADERS: xforwarded
YAML
    COMPOSE_FILES="$COMPOSE_FILES -f $PROXY_OVERRIDE"
  fi
  echo "    Keycloak: http://localhost:$EXTERNAL_PORT"
  echo "    Admin console: http://localhost:$EXTERNAL_PORT/admin"
  ${KC_WRAPPER:-} docker compose $COMPOSE_FILES up keycloak
else
  echo "==> Starting ngrok + Keycloak..."
  NGROK_ARGS=""
  if [ -n "$NGROK_DOMAIN" ]; then
    NGROK_ARGS="--domain $NGROK_DOMAIN"
  fi
  if [ "$NGROK_ONLY" = "true" ]; then
    NGROK_ARGS="$NGROK_ARGS --ngrok-only"
  fi
  "$ROOT_DIR/scripts/run-keycloak-ngrok.sh" $NGROK_ARGS
fi
