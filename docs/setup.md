# Setup Guide

The demo realm (`core/src/test/resources/realm-wallet-demo-local.json`) is a working example of this configuration.

## Step 1: Deployment

Build the shaded provider jar and copy it into Keycloak's `providers/` directory:

```bash
mvn package -DskipTests
cp core/target/keycloak-extension-oid4vp.jar /opt/keycloak/providers/
```

`docker-compose.yml` mounts `core/target/keycloak-extension-oid4vp.jar`.

## Step 2: Identity Provider

1. Open the Keycloak Admin Console.
2. Go to **Identity Providers**.
3. Select **OID4VP**.
4. Configure the provider settings.

For transient wallet logins, start Keycloak with the `transient-users` feature and enable the IdP option **Do not store users**.

Keycloak's experimental `oid4vc-vp` feature ships its own OID4VP identity provider and SD-JWT mappers under the same provider ids (`oid4vp`, `oid4vp-sd-jwt-user-attribute-idp-mapper`, `oid4vp-sd-jwt-user-session-attribute-idp-mapper`). The extension overrides them, so leave that feature disabled.

Example realm import fragment:

```json
{
  "identityProviders": [
    {
      "alias": "oid4vp",
      "displayName": "Sign in with Wallet",
      "providerId": "oid4vp",
      "enabled": true,
      "config": {
        "clientIdScheme": "x509_san_dns",
        "responseMode": "direct_post.jwt",
        "x509CertificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "walletScheme": "openid4vp://"
      }
    }
  ]
}
```

## Step 3: Trust

Add an `etsi-trust-list` identity provider for each trust domain, and name these providers in `trustMaterialIdps` of the OID4VP identity provider. Pin the list signer through `trustListSigningCertPem`, because Keycloak trusts a list without one as fetched. Only the configured keys count, and an `x5c` chain in the list is ignored. See [ETSI Trust List Provider](configuration.md#etsi-trust-list-provider).

## Step 4: Mappers

Keycloak generates the DCQL query from the OID4VP mappers, so each claim you request needs a mapper. Set `principalAttributes` to the claim that identifies the user. See [IdP Mappers](configuration.md#idp-mappers) and [Subject Claim](configuration.md#subject-claim).

## Step 5: Events (Optional)

The extension reports security events as Keycloak events. To see them in the Admin Console, turn on the realm's save events switch and enable the identity provider event types. See [Security Events](events.md).
