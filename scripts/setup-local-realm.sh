#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

REALM_OUT="${ROOT_DIR}/src/test/resources/realm-wallet-demo-local.json"

usage() {
  cat <<'EOF'
Usage: scripts/setup-local-realm.sh <pem-file> <verifier-info-file> [trust-list-url]

Generates src/test/resources/realm-wallet-demo-local.json for local testing
with the provided X.509 credentials and verifier info.

Arguments:
  <pem-file>             Path to combined PEM file (cert chain + private key)
  <verifier-info-file>   Path to JSON file containing verifier attestations
  [trust-list-url]       Optional trust list URL override (default: BMI test trust list)

The generated files are gitignored and specific to your local environment.

Example:
  scripts/setup-local-realm.sh /path/to/combined.pem /path/to/verifier-info.json
  scripts/setup-local-realm.sh /path/to/combined.pem /path/to/verifier-info.json http://host.docker.internal:8085/api/trustlist
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
TRUST_LIST_URL="${3:-https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt}"

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
  "registrationAllowed": false,
  "roles": {
    "realm": [
      {
        "name": "default-roles-wallet-demo",
        "description": "\${role_default-roles}",
        "composite": true,
        "composites": {
          "client": {
            "account": [
              "manage-account",
              "manage-account-links",
              "view-profile"
            ]
          }
        },
        "clientRole": false
      }
    ],
    "client": {
      "account": [
        {
          "name": "manage-account",
          "description": "\${role_manage-account}",
          "composite": true,
          "composites": {
            "client": {
              "account": ["manage-account-links"]
            }
          },
          "clientRole": true
        },
        {
          "name": "manage-account-links",
          "description": "\${role_manage-account-links}",
          "composite": false,
          "clientRole": true
        },
        {
          "name": "view-profile",
          "description": "\${role_view-profile}",
          "composite": false,
          "clientRole": true
        }
      ]
    }
  },
  "defaultRole": {
    "name": "default-roles-wallet-demo",
    "description": "\${role_default-roles}",
    "composite": true,
    "clientRole": false
  },
  "clientScopeMappings": {
    "account": [
      {
        "client": "account-console",
        "roles": ["manage-account", "view-groups"]
      }
    ]
  },
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
    },
    {
      "clientId": "account",
      "name": "\${client_account}",
      "rootUrl": "\${authBaseUrl}",
      "baseUrl": "/realms/wallet-demo/account/",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "protocol": "openid-connect",
      "redirectUris": ["/realms/wallet-demo/account/*"],
      "webOrigins": ["*"],
      "fullScopeAllowed": false,
      "attributes": {
        "post.logout.redirect.uris": "+"
      },
      "defaultClientScopes": ["web-origins", "acr", "profile", "roles", "basic", "email"],
      "optionalClientScopes": ["address", "phone", "organization", "offline_access", "microprofile-jwt"]
    },
    {
      "clientId": "account-console",
      "name": "\${client_account-console}",
      "rootUrl": "\${authBaseUrl}",
      "baseUrl": "/realms/wallet-demo/account/",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "protocol": "openid-connect",
      "redirectUris": ["/realms/wallet-demo/account/*"],
      "webOrigins": ["*"],
      "fullScopeAllowed": false,
      "attributes": {
        "post.logout.redirect.uris": "+",
        "pkce.code.challenge.method": "S256"
      },
      "protocolMappers": [
        {
          "name": "audience resolve",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-resolve-mapper",
          "consentRequired": false,
          "config": {}
        }
      ],
      "defaultClientScopes": ["web-origins", "acr", "profile", "roles", "basic", "email"],
      "optionalClientScopes": ["address", "phone", "organization", "offline_access", "microprofile-jwt"]
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
        "trustListUrl": "${TRUST_LIST_URL}",
        "clientIdScheme": "x509_san_dns",
        "walletScheme": "openid4vp://",
        "userMappingClaim": "family_name",
        "userMappingClaimMdoc": "family_name",
        "trustListLoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
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
      "name": "sd-jwt-country-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address/country",
        "user.attribute": "address.country"
      }
    },
    {
      "name": "sd-jwt-region-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address/region",
        "user.attribute": "address.region"
      }
    },
    {
      "name": "sd-jwt-postal_code-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "address/postal_code",
        "user.attribute": "address.postal_code"
      }
    },
    {
      "name": "sd-jwt-place_of_birth-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "place_of_birth/locality",
        "user.attribute": "place_of_birth"
      }
    },
    {
      "name": "sd-jwt-date_of_expiry-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "date_of_expiry",
        "user.attribute": "date_of_expiry"
      }
    },
    {
      "name": "sd-jwt-issuing_authority-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "issuing_authority",
        "user.attribute": "issuing_authority"
      }
    },
    {
      "name": "sd-jwt-issuing_country-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "dc+sd-jwt",
        "credential.type": "urn:eudi:pid:de:1",
        "claim": "issuing_country",
        "user.attribute": "issuing_country"
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
      "name": "mdoc-place_of_birth-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "birth_place/locality",
        "user.attribute": "place_of_birth"
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
        "multivalued": "true",
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
        "multivalued": "true",
        "user.attribute": "nationality"
      }
    },
    {
      "name": "mdoc-resident_country-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "resident_country",
        "user.attribute": "resident_country"
      }
    },
    {
      "name": "mdoc-resident_state-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "resident_state",
        "user.attribute": "resident_state"
      }
    },
    {
      "name": "mdoc-resident_postal_code-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "resident_postal_code",
        "user.attribute": "resident_postal_code"
      }
    },
    {
      "name": "mdoc-expiry_date-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "expiry_date",
        "user.attribute": "expiry_date"
      }
    },
    {
      "name": "mdoc-issuing_authority-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "issuing_authority",
        "user.attribute": "issuing_authority"
      }
    },
    {
      "name": "mdoc-issuing_country-to-attribute",
      "identityProviderAlias": "oid4vp",
      "identityProviderMapper": "oid4vp-user-attribute-mapper",
      "config": {
        "syncMode": "INHERIT",
        "credential.format": "mso_mdoc",
        "credential.type": "eu.europa.ec.eudi.pid.1",
        "claim": "issuing_country",
        "user.attribute": "issuing_country"
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
