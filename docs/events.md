# Security Events

The extension reports security relevant decisions as standard Keycloak events. They reach the event listeners enabled in the realm, for example `jboss-logging`, and the event store. Events hold no credential claims.

## Event Types

Keycloak has a fixed list of event types, so every event uses an identity provider event type and names the OID4VP event in the `oid4vp_event_type` detail.

| OID4VP Event Type | When Fired | Keycloak Event Type | Error Code |
|-------------------|------------|---------------------|------------|
| `PRESENTATION_VERIFIED` | A wallet presentation passed verification. A repeated verified presentation for the same state fires none | `IDENTITY_PROVIDER_RESPONSE` | - |
| `PRESENTATION_FAILED` | A wallet response ended without a verified presentation | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_presentation_failed` |
| `PRESENTATION_REFUSED` | A login or a verified presentation does not meet what the flow requires | `IDENTITY_PROVIDER_LOGIN_ERROR`, or `IDENTITY_PROVIDER_RESPONSE_ERROR` for `CREDENTIAL_IGNORED`, because that login continues | `oid4vp_presentation_refused` |
| `COMPLETION_REJECTED` | Keycloak refused a step towards completing a login | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_completion_rejected` |
| `REVOCATION_DETECTED` | A status list or CRL marks a credential or an issuer certificate as revoked or suspended | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_revocation_detected` |
| `REVOCATION_CHECK_FAILED` | A revocation status could not be determined | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_revocation_check_failed` |
| `TRUST_MATERIAL_FAILED` | Trust material is missing or weaker than configured | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_trust_material_failed` |

## Details

The event details carry the data under `oid4vp_` keys, which `Oid4vpEventDetails` defines.

| Detail | Events | Meaning |
|--------|--------|---------|
| `oid4vp_identity_provider` | Presentation and completion events | Alias of the OID4VP identity provider |
| `oid4vp_state` | Presentation, completion and revocation events | OID4VP state of the login |
| `oid4vp_flow` | `PRESENTATION_VERIFIED`, `PRESENTATION_FAILED` | `same_device` or `cross_device` |
| `oid4vp_credential_types` | `PRESENTATION_VERIFIED` | Comma separated VCTs and doctypes |
| `oid4vp_trust_provider` | Revocation and trust material events | Internal id of the trust material identity provider |
| `oid4vp_reference` | Revocation and trust material events | Status list URI, CRL URLs or trust list URL |
| `oid4vp_stale_data_in_use` | `REVOCATION_CHECK_FAILED`, `TRUST_MATERIAL_FAILED` | `true` when a last known CRL or a stale trust list still applies |
| `oid4vp_error` | `PRESENTATION_FAILED` | Error code of a wallet error response |
| `oid4vp_reason` | All errors | Free text that can change |
| `oid4vp_origin`, `oid4vp_refusal`, `oid4vp_rejection`, `oid4vp_mechanism`, `oid4vp_failure` | See below | Values to match on |

| Detail | Value | Meaning |
|--------|-------|---------|
| `oid4vp_origin` | `VERIFIER` | Verification rejected the presentation |
| | `SERVER` | Verification broke on the server side, a status list or a required CRL was unavailable, or a credential had no issuer trust because a trust list had no usable copy. The presentation received no verdict |
| | `WALLET` | The wallet answered with an error response, which nothing authenticates. A user who declines ends up here |
| | `TRANSPORT` | The post failed before its presentation could be verified, for example an undecryptable or unencrypted response |
| `oid4vp_refusal` | `USER_MISMATCH` | The presentation does not fit the user of the authentication flow |
| | `LEVEL_NOT_OFFERED` | No OID4VP flow offers the requested level of authentication |
| | `CREDENTIAL_IGNORED` | Keycloak left a credential out, because it was issued for another presentation or lacks a reference binding. The login continues without it |
| `oid4vp_rejection` | `RESPONSE_CODE` | The state has no record, or the response code does not match it |
| | `BROWSER_MISMATCH` | The browser is not the one that started the login |
| | `REPEATED_PRESENTATION` | A further verified presentation arrived for a state that already has one. A wallet retry looks the same. The first presentation stays in force |
| `oid4vp_mechanism` | `STATUS_LIST`, `CRL`, `IDENTIFIER_LIST` | How the revocation is published. `IDENTIFIER_LIST` only occurs on `REVOCATION_CHECK_FAILED`, because the extension does not read identifier lists |
| `oid4vp_failure` | `REFRESH_FAILED` | A trust list could not be fetched or verified, or it is closed. Fires at most once per provider and request, and not during the retry pause. Without a stale copy the list adds no certificates |
| | `UNSIGNED` | Keycloak read a trust list without a signature check, once per provider on each node, before it parses the list, or a status list, once per download |
| | `UNAVAILABLE` | None of the configured trust material identity providers resolved, so Keycloak rejects every credential |

- Wallets and issuers control parts of `oid4vp_reason`, `oid4vp_reference`, `oid4vp_state` and `oid4vp_error`, so treat them as untrusted text. Each value is reduced to one line and cut at 1024 characters.
- The client and the user are set where known. Most events have no user.
- `PRESENTATION_REFUSED` carries `oid4vp_state` only for `CREDENTIAL_IGNORED`.
- Status list events, identifier list events and `UNAVAILABLE` have no `oid4vp_trust_provider`.
- An event from a background CRL refresh has neither `oid4vp_state` nor an IP address.

## Reading Revocation Events

A `REVOCATION_CHECK_FAILED` event does not say whether the login goes on:

- A failed status list check rejects the credential.
- A CRL check without a known CRL rejects the credential with `crlRequired` and accepts it unchecked otherwise. Without `crlRequired` the event fires once per failed download and for each login that waited. Later logins fire none until the cache TTL ends.
- An identifier list stays unchecked, and a credential with both an identifier list and a status list still gets the status list check.

A rejection also fires `PRESENTATION_FAILED` with the same `oid4vp_state`, and a revocation rejection fires `REVOCATION_DETECTED` as well. An event with an `oid4vp_state` and no such match means the credential continued, unchecked unless `oid4vp_stale_data_in_use` is `true`.

## Storing and Logging Events

- **Listeners:** the event listeners enabled in the realm receive every event. Realms enable `jboss-logging` by default, which logs errors at WARN.
- **Event store:** Keycloak saves these identity provider event types only when they are enabled. Turn on the realm's save events switch and enable `IDENTITY_PROVIDER_RESPONSE`, `IDENTITY_PROVIDER_RESPONSE_ERROR` and `IDENTITY_PROVIDER_LOGIN_ERROR`.
- **Brute force protection:** the events use identity provider event types and add no `LOGIN_ERROR`, so they do not change brute force counts.
- **Unauthenticated requests:** `COMPLETION_REJECTED` and `PRESENTATION_FAILED` with origin `TRANSPORT` fire on unauthenticated requests, so a client can cause event store writes.
