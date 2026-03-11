#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/run-keycloak-ngrok.sh [--domain <name>] [--ngrok-only]

Starts ngrok and Keycloak (via docker compose) with a public HTTPS URL.
Keycloak is configured with KC_HOSTNAME so it generates correct endpoint URLs.

Prerequisites:
  - mvn package must have been run first (to build target/providers/)
  - ngrok must be installed and authenticated
  - docker must be running

Options:
  --domain <name>  Use a custom ngrok domain (registered in your ngrok account).
  --ngrok-only     Start only ngrok and print env vars.

Examples:
  scripts/run-keycloak-ngrok.sh
  scripts/run-keycloak-ngrok.sh --domain mykeycloak.ngrok-free.app
  scripts/run-keycloak-ngrok.sh --ngrok-only
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

KC_PORT="${NGROK_TARGET_PORT:-8080}"
NGROK_ONLY=false
NGROK_DOMAIN=""

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --domain)
      if [ $# -lt 2 ]; then
        echo "Missing value for --domain" >&2
        usage >&2
        exit 2
      fi
      NGROK_DOMAIN="$2"
      shift 2
      ;;
    --ngrok-only|--tunnel-only)
      NGROK_ONLY=true
      shift
      ;;
    *)
      echo "Unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd ngrok
require_cmd curl
require_cmd jq
require_cmd docker

# Build providers if not already present
if [ ! -d "$ROOT_DIR/target/providers" ]; then
  echo "==> Building extension (target/providers/ not found)..."
  (cd "$ROOT_DIR" && mvn package -DskipTests -q)
  echo "    Build complete."
fi

tmp_log="$(mktemp -t keycloak-ngrok.XXXXXX.log)"

cleanup() {
  if [ -n "${NGROK_PID:-}" ]; then
    kill "${NGROK_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "$tmp_log" >/dev/null 2>&1 || true
}

trap cleanup INT TERM EXIT

# Start ngrok
NGROK_ARGS="http $KC_PORT --log=stdout --log-format=json"
if [ -n "$NGROK_DOMAIN" ]; then
  NGROK_ARGS="$NGROK_ARGS --url=$NGROK_DOMAIN"
fi
ngrok $NGROK_ARGS >"$tmp_log" 2>&1 &
NGROK_PID="$!"

get_public_url() {
  for api_port in 4040 4041 4042 4043 4044 4045; do
    public_url="$(curl -fsS "http://127.0.0.1:${api_port}/api/tunnels" 2>/dev/null \
      | jq -r --arg addr "localhost:${KC_PORT}" '.tunnels[] | select(.proto=="https" and (.config.addr | endswith($addr) or contains($addr))) | .public_url' 2>/dev/null \
      | head -n 1)"
    if [ -n "$public_url" ]; then
      printf '%s\n' "$public_url"
      return 0
    fi
  done
  return 1
}

# Wait for ngrok to be ready
i=0
public_url=""
while [ "$i" -lt 120 ]; do
  public_url="$(get_public_url || true)"
  if [ -n "$public_url" ] && [ "$public_url" != "null" ]; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

if [ -z "$public_url" ] || [ "$public_url" = "null" ]; then
  echo "Failed to obtain ngrok public URL. See: $tmp_log" >&2
  exit 1
fi

cat <<EOF
ngrok is running (pid $NGROK_PID)

Keycloak public URL:
  $public_url

Keycloak admin console:
  $public_url/admin

ngrok dashboard:
  http://127.0.0.1:4040 (or the next free port if 4040 is busy)

Env vars:
  KC_HOSTNAME=$public_url
  KC_PROXY_HEADERS=xforwarded
EOF

if [ "$NGROK_ONLY" = "true" ]; then
  cat <<EOF

To start Keycloak with this hostname, run in another terminal:
  KC_HOSTNAME=$public_url KC_PROXY_HEADERS=xforwarded docker compose up keycloak
  (Run scripts/setup-local-realm.sh first if you have local credentials)

Press Ctrl+C to stop ngrok.
EOF
  wait "$NGROK_PID"
  exit 0
fi

echo ""
echo "Starting Keycloak via docker compose..."

cd "$ROOT_DIR"
NGROK_OVERRIDE="$ROOT_DIR/docker-compose.ngrok.yml"
cat > "$NGROK_OVERRIDE" <<YAML
services:
  keycloak:
    environment:
      KC_HOSTNAME: "$public_url"
      KC_PROXY_HEADERS: xforwarded
YAML

cleanup_override() {
  rm -f "$NGROK_OVERRIDE" >/dev/null 2>&1 || true
}
# Add to existing trap
trap 'cleanup; cleanup_override' INT TERM EXIT

${KC_WRAPPER:-} docker compose -f docker-compose.yml -f "$NGROK_OVERRIDE" up keycloak
