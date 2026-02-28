#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Sensible defaults – override via flags or env vars
DEFAULT_SANDBOX_DIR="${SANDBOX_DIR:-${ROOT_DIR}/sandbox}"
DEFAULT_PEM_FILE="${DEFAULT_SANDBOX_DIR}/sandbox-ngrok-combined.pem"
DEFAULT_VERIFIER_INFO="${DEFAULT_SANDBOX_DIR}/sandbox-verifier-info.json"

usage() {
  cat <<'EOF'
Usage: scripts/dev.sh [options]

One-command local development: builds the extension, generates realm config
from sandbox certificates, and starts Keycloak (optionally behind an ngrok tunnel).

Options:
  --pem <file>             Combined PEM file (cert chain + private key)
                           Default: sandbox/sandbox-ngrok-combined.pem
  --verifier-info <file>   Verifier attestation JSON file
                           Default: sandbox/sandbox-verifier-info.json
  --domain <name>          Custom ngrok domain (overrides auto-detection)
                           Default: extracted from SAN DNS in PEM cert, or none
  --no-build               Skip Maven build (use existing target/providers/)
  --skip-realm             Skip realm generation (use existing local realm)
  --no-proxy               Disable oid4vc-dev proxy even if available
  --no-ngrok               Run Keycloak without ngrok (localhost only)
  --ngrok-only             Start only ngrok tunnel, no Keycloak
  -h, --help               Show this help

Environment variables (override defaults):
  SANDBOX_DIR              Base directory for sandbox certs
                           Default: sandbox/

Examples:
  scripts/dev.sh                                       # Everything with defaults
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

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
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

# Step 1: Build
if [ "$DO_BUILD" = "true" ]; then
  echo "==> Building extension..."
  (cd "$ROOT_DIR" && mvn package -DskipTests -q)
  echo "    Build complete."
else
  if [ ! -d "$ROOT_DIR/target/providers" ]; then
    echo "target/providers/ not found. Run without --no-build or build manually." >&2
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
  "$ROOT_DIR/scripts/setup-local-realm.sh" "$PEM_FILE" "$VERIFIER_INFO"
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

# Step 4: Start Keycloak (with or without ngrok)
if [ "$DO_NGROK" = "false" ]; then
  echo "==> Starting Keycloak (localhost only)..."
  cd "$ROOT_DIR"
  echo "    Keycloak: http://localhost:$KC_PORT"
  echo "    Admin console: http://localhost:$KC_PORT/admin"
  ${KC_WRAPPER:-} docker compose up keycloak
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
