#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

REALM_OUT="${ROOT_DIR}/src/test/resources/realm-wallet-demo-local.json"

usage() {
  cat <<'EOF'
Usage: scripts/setup-local-realm.sh <pem-file> <verifier-info-file>

Generates src/test/resources/realm-wallet-demo-local.json for local testing
with the provided X.509 credentials and verifier info.

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
        "userMappingClaim": "family_name",
        "userMappingClaimMdoc": "family_name",
        "allowedCredentialTypes": "urn:eudi:pid:de:1,eu.europa.ec.eudi.pid.1",
        "x509CertificatePem": "${PEM_CONTENT}",
        "verifierInfo": "${VERIFIER_INFO_CONTENT}"
      }
    }
  ],
  "identityProviderMappers": [
    {
      "name": "sd-jwt-family_name-to-lastName",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "family_name",
        "user.attribute": "lastName"
      }
    },
    {
      "name": "sd-jwt-given_name-to-firstName",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "given_name",
        "user.attribute": "firstName"
      }
    },
    {
      "name": "sd-jwt-birthdate-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "birthdate",
        "user.attribute": "birthdate"
      }
    },
    {
      "name": "mdoc-family_name-to-lastName",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "family_name",
        "user.attribute": "lastName"
      }
    },
    {
      "name": "mdoc-given_name-to-firstName",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "given_name",
        "user.attribute": "firstName"
      }
    },
    {
      "name": "mdoc-birth_date-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "birth_date",
        "user.attribute": "birthdate"
      }
    },
    {
      "name": "sd-jwt-address-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address",
        "user.attribute": "address"
      }
    },
    {
      "name": "sd-jwt-street_address-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address/street_address",
        "user.attribute": "address.street_address"
      }
    },
    {
      "name": "sd-jwt-locality-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address/locality",
        "user.attribute": "address.locality"
      }
    },
    {
      "name": "mdoc-resident_street-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "resident_street",
        "user.attribute": "resident_street"
      }
    },
    {
      "name": "mdoc-resident_city-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "resident_city",
        "user.attribute": "resident_city"
      }
    },
    {
      "name": "sd-jwt-nationalities-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "nationalities/null",
        "user.attribute": "nationality"
      }
    },
    {
      "name": "mdoc-nationality-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "nationality",
        "user.attribute": "nationality"
      }
    }
  ]
}
REALMEOF

echo "Generated:"
echo "  $REALM_OUT"
echo ""
echo "Usage:"
echo "  mvn package -DskipTests"
echo "  scripts/run-keycloak-ngrok.sh"
echo ""
echo "The local realm will be auto-imported on Keycloak startup."
