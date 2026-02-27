#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

REALM_OUT="${ROOT_DIR}/realm-wallet-demo-local.json"
COMPOSE_OUT="${ROOT_DIR}/docker-compose.local.yml"

usage() {
  cat <<'EOF'
Usage: scripts/setup-local-realm.sh <pem-file> <verifier-info-file>

Generates realm-wallet-demo-local.json and docker-compose.local.yml for
local testing with the provided X.509 credentials and verifier info.

Arguments:
  <pem-file>             Path to combined PEM file (cert chain + private key)
  <verifier-info-file>   Path to JSON file containing verifier attestations

The generated files are gitignored and specific to your local environment.

Example:
  scripts/setup-local-realm.sh /path/to/combined.pem /path/to/verifier-info.json
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ $# -lt 2 ]; then
  echo "Error: expected 2 arguments, got $#" >&2
  echo "" >&2
  usage >&2
  exit 2
fi

PEM_FILE="$1"
VERIFIER_INFO_FILE="$2"

if [ ! -f "$PEM_FILE" ]; then
  echo "PEM file not found: $PEM_FILE" >&2
  exit 1
fi

if [ ! -f "$VERIFIER_INFO_FILE" ]; then
  echo "Verifier info file not found: $VERIFIER_INFO_FILE" >&2
  exit 1
fi

# Read and escape for JSON embedding
PEM_CONTENT=$(cat "$PEM_FILE" | sed 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//')
VERIFIER_INFO_CONTENT=$(cat "$VERIFIER_INFO_FILE" | tr -d '\n' | sed 's/"/\\"/g')

cat > "$REALM_OUT" <<REALMEOF
{
  "realm": "wallet-demo",
  "enabled": true,
  "loginTheme": "oid4vp",
  "registrationAllowed": false,
  "clients": [
    {
      "clientId": "wallet-mock",
      "enabled": true,
      "publicClient": true,
      "directAccessGrantsEnabled": true,
      "redirectUris": ["*"],
      "webOrigins": ["*"],
      "protocol": "openid-connect",
      "standardFlowEnabled": true,
      "attributes": {
        "pkce.code.challenge.method": "S256"
      }
    }
  ],
  "users": [
    {
      "username": "admin",
      "enabled": true,
      "credentials": [
        {
          "type": "password",
          "value": "admin",
          "temporary": false
        }
      ],
      "realmRoles": ["admin"]
    }
  ],
  "identityProviders": [
    {
      "alias": "oid4vp",
      "displayName": "Sign in with Wallet",
      "providerId": "oid4vp",
      "enabled": true,
      "trustEmail": false,
      "storeToken": false,
      "addReadTokenRoleOnCreate": false,
      "authenticateByDefault": false,
      "linkOnly": false,
      "firstBrokerLoginFlowAlias": "first broker login",
      "config": {
        "clientId": "not-used",
        "clientSecret": "not-used",
        "enforceHaip": "true",
        "skipTrustListVerification": "true",
        "trustX5cFromCredential": "true",
        "clientIdScheme": "x509_san_dns",
        "walletScheme": "openid4vp://",
        "userMappingClaim": "document_number",
        "userMappingClaimMdoc": "document_number",
        "x509CertificatePem": "${PEM_CONTENT}",
        "verifierInfo": "${VERIFIER_INFO_CONTENT}",
        "dcqlQuery": "{\"credentials\":[{\"id\":\"pid_sd_jwt\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"urn:eudi:pid:1\"]},\"claims\":[{\"path\":[\"document_number\"]},{\"path\":[\"family_name\"]},{\"path\":[\"given_name\"]},{\"path\":[\"birthdate\"]}]},{\"id\":\"pid_mdoc\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"eu.europa.ec.eudi.pid.1\"},\"claims\":[{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"document_number\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"family_name\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"given_name\"]},{\"path\":[\"eu.europa.ec.eudi.pid.1\",\"birth_date\"]}]}],\"credential_sets\":[{\"options\":[[\"pid_sd_jwt\"],[\"pid_mdoc\"]],\"required\":true}]}"
      }
    }
  ]
}
REALMEOF

cat > "$COMPOSE_OUT" <<'COMPOSEEOF'
services:
  keycloak:
    volumes:
      - ./realm-wallet-demo-local.json:/opt/keycloak/data/import/realm-wallet-demo-local.json:ro
COMPOSEEOF

echo "Generated:"
echo "  $REALM_OUT"
echo "  $COMPOSE_OUT"
echo ""
echo "Usage:"
echo "  mvn package -DskipTests"
echo "  scripts/run-keycloak-ngrok.sh"
echo ""
echo "The local realm will be auto-imported on Keycloak startup."
