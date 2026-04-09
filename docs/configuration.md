# Configuration

The extension is configured as a Keycloak identity provider. All settings are stored in the IdP provider config and can be managed through the Admin UI or realm import JSON.

## Adding the Identity Provider

1. Open the Keycloak Admin Console.
2. Go to **Identity Providers**.
3. Select **OID4VP**.
4. Configure the provider settings.

If you want transient wallet logins, Keycloak must be started with the `transient-users` feature enabled. Then enable the IdP's built-in **Do not store users** option in Keycloak.

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
        "walletScheme": "openid4vp://",
        "enforceHaip": "false",
        "dcqlQuery": "{...}"
      }
    }
  ]
}
```

## Settings

### Credential Request

| Key | Description | Default |
|-----|-------------|---------|
| `dcqlQuery` | DCQL query JSON defining which credentials to request. If omitted, Keycloak derives the query from configured OID4VP mappers. Manual queries are normalized by filling in missing format metadata and, when enabled, `trusted_authorities`. | *(auto-generated)* |
| `credentialSetMode` | How credential sets are combined: `optional` or `all`. | `optional` |
| `credentialSetPurpose` | Human-readable purpose string included in the DCQL credential set. | *(none)* |
| `requestObjectLifespanSeconds` | Lifespan of the signed request object JWT used by the wallet fetch. | `10` |

### User Mapping

| Key | Description | Default |
|-----|-------------|---------|
| `userMappingClaim` | Claim from an SD-JWT credential used as the unique user identifier. Not required when `useIdTokenSubject` is enabled. Ignored when OID4VP transient users are enabled. | `sub` |
| `userMappingClaimMdoc` | Claim from an mDoc credential used as the unique user identifier. Falls back to `userMappingClaim`. Ignored when OID4VP transient users are enabled. | *(falls back)* |
| `useIdTokenSubject` | When HAIP is disabled, requests an additional self-issued `id_token` and uses its subject as the user identifier. The VP token remains required for credential attributes. Ignored when HAIP is enabled. | `false` |
| `doNotStoreUsers` | Native Keycloak IdP setting. When enabled, OID4VP switches to transient per-login identities, ignores configured identifying claims, and relies on Keycloak transient users. Requires the Keycloak `transient-users` feature to be enabled. | `false` |
| `clockSkewSeconds` | Allowed clock skew for ID token time checks. | `60` |

### Transient Login Mode

To use this extension as a wallet connector without creating persisted Keycloak users:

1. Start Keycloak with the `transient-users` feature enabled.
2. Enable the IdP's built-in **Do not store users** setting.
3. Keep using the normal first broker login flow. Keycloak will create a `LightweightUserAdapter` and a transient user session instead of a stored user.

Behavior in this mode:

- The extension always generates a random per-login transient identifier.
- `userMappingClaim`, `userMappingClaimMdoc`, and `useIdTokenSubject` are ignored for subject resolution.
- OID4VP user-attribute mappers still apply, but the target user is transient and is not persisted after the session ends.
- Session-note mappers are often the best fit when relying parties only need token-time claim propagation.

This mode is intended for credentials that do not carry a stable account identifier, such as German PID variants.

### Flow Control

| Key | Description | Default |
|-----|-------------|---------|
| `sameDeviceEnabled` | Enables same-device wallet login. | `true` |
| `crossDeviceEnabled` | Enables cross-device QR-code wallet login. | `true` |
| `walletScheme` | URI scheme used to invoke the wallet app. | `openid4vp://` |
| `responseMode` | Wallet callback response mode: `direct_post` or `direct_post.jwt`. | `direct_post` |

### Client Authentication (X.509)

| Key | Description | Default |
|-----|-------------|---------|
| `clientIdScheme` | Wallet/verifier client ID scheme: `plain`, `x509_san_dns`, or `x509_hash`. | `x509_san_dns` |
| `x509CertificatePem` | PEM-encoded verifier certificate material used for client ID derivation and request-object header material. | *(required for x509 schemes)* |
| `x509SigningKeyJwk` | Explicit signing JWK override. Normally derived automatically. | *(auto-derived)* |
| `verifierInfo` | JSON value for the request object's `verifier_info` claim. | *(none)* |

`x509CertificatePem` supports two practical layouts:

1. Combined PEM with leaf certificate, optional intermediate certificates, and private key.
2. Certificate-only PEM when request objects should be signed with the Keycloak realm signing key instead.

### Trust and Verification

| Key | Description | Default |
|-----|-------------|---------|
| `enforceHaip` | Enables the HAIP-oriented effective configuration (`direct_post.jwt` and `x509_hash`). | `true` |
| `trustListUrl` | URL of an ETSI TS 119 602 trust list JWT. | *(none)* |
| `trustListLoTEType` | Expected trust-list LoTE type for this IdP. Keep one trust domain per OID4VP IdP instance. Leave empty only to accept all LoTE types from the configured trust list. | empty |
| `trustedAuthoritiesMode` | DCQL `trusted_authorities` mode: `none`, `etsi_tl`, or `aki`. | `none` |
| `trustListSigningCertPem` | PEM-encoded certificate chain used to verify the trust list JWT signature. If omitted, the trust list JWT is not signature-verified. | *(none)* |
| `allowedIssuers` | Comma-separated list of allowed SD-JWT issuer (`iss`) values, or `*`. mDoc credentials are not checked against this list because mDoc does not define a standard canonical credential-issuer string equivalent to SD-JWT `iss`. | `*` |
| `clockSkewSeconds` | Clock skew tolerance for credential verification. | `60` |
| `kbJwtMaxAgeSeconds` | Maximum accepted age of the SD-JWT KB-JWT `iat` claim. | `300` |

For SD-JWT VC verification, the verifier tries issuer-key resolution in this order:

1. `x5c` certificate-chain validation against the trust list
2. When HAIP is disabled, JWT VC issuer metadata lookup via `iss` + JOSE `kid` from `/.well-known/jwt-vc-issuer`, including `jwks_uri`
3. Final direct trusted-certificate fallback for non-HAIP deployments

When `enforceHaip=true`, only the `x5c` path is attempted.

By default, the verifier only trusts the credential types this IdP actually requested in its DCQL query. Those types come from:

- the configured `dcqlQuery`, or
- mapper-derived credential types when `dcqlQuery` is empty

Use one OID4VP IdP instance per trust domain. If `trustListLoTEType` is configured, it must match the fetched trust list's `ListAndSchemeInformation.LoTEType`. If it is left empty, all LoTE types from that trust list are accepted and the provider logs a warning.
Within the accepted trust list, credential signature verification uses only `.../SvcType/.../Issuance` services. Status-list JWT verification uses only `.../SvcType/.../Revocation` services.

### Caching

Trust lists are cached until the earliest of ETSI `ListAndSchemeInformation.NextUpdate`, HTTP cache headers, and `trustListMaxCacheTtlSeconds` when configured. A trust list whose `NextUpdate` is already in the past is discarded as expired. Trust-list responses without `NextUpdate` are not cached and are not reused as stale fallback. Status lists are cached according to their `ttl` claim when present, capped by `exp` if present; if `ttl` is absent they fall back to `exp`. Status-list responses without both `ttl` and `exp` are treated as immediately expired. JWT VC issuer metadata caching is bounded by HTTP cache headers, `issuerMetadataMaxCacheTtlSeconds`, and each JWK's optional `exp`, whichever expires first.

| Key | Description | Default |
|-----|-------------|---------|
| `statusListMaxCacheTtlSeconds` | Optional maximum cache TTL for token status lists. The effective lifetime uses status-list `ttl` when present, capped by `exp`; otherwise it falls back to `exp`. | *(use status-list ttl / exp)* |
| `trustListMaxCacheTtlSeconds` | Optional maximum cache TTL for trust lists. The effective lifetime is capped earlier by ETSI `NextUpdate` and HTTP cache headers. | *(use trust-list freshness metadata)* |
| `trustListMaxStaleAgeSeconds` | Maximum age of an expired trust-list cache entry that may be reused when refresh fails. Set `0` to disable stale fallback. | `86400` |
| `issuerMetadataMaxCacheTtlSeconds` | Optional maximum cache TTL for JWT VC issuer metadata and resolved issuer JWKS. The effective lifetime is capped earlier by HTTP `Cache-Control` and any JWK `exp`. Set `0` to disable issuer-metadata caching. | `86400` |

### Cross-Device SSE

| Key | Description | Default |
|-----|-------------|---------|
| `ssePollIntervalMs` | How often each SSE connection polls shared completion state. | `2000` |
| `sseTimeoutSeconds` | Maximum SSE connection lifetime before timeout. | `120` |
| `ssePingIntervalSeconds` | Keep-alive ping interval. | `10` |
| `crossDeviceCompleteTtlSeconds` | Lifetime of the cross-device completion marker. The deferred auth record itself uses the realm login timeout. | `300` |

## IdP Mappers

The extension provides two mapper types:

- `OID4VP Claim to User Attribute`
- `OID4VP Claim to User Session Note`

Each mapper declares a credential format, credential type, and claim path. When `dcqlQuery` is not set manually, these mappers drive the generated DCQL request.

## Multi-Node Behavior

Cross-device completion depends on a shared Keycloak `SingleUseObjectProvider`. Each node keeps only its local SSE connections; every open cross-device watcher polls the shared completion marker from a virtual thread on the node currently serving that browser connection. No cluster notification channel is required, but the single-use object store itself must be shared.
