# SPI Reference

## Reference Credential Binding SPI

The credential this Keycloak issues identifies an account on its own, so it needs a link to the PID it was issued with. Without that link, one person's employee credential next to another person's PID would sign in as the first person.

- The issued credential carries a keyed digest of the credential types and claims it was issued alongside.
- The verifier recomputes the digest from the current presentation.
- On a mismatch it treats the credential as not presented, so neither its subject nor its claims reach the login.
- The digest is an HMAC over a realm secret, because a plain hash of names and dates can be recovered from a candidate list. Passive realm keys still verify, so a key rotation keeps issued credentials valid.
- The binding covers claims of the person, so re-issued and batch-issued PIDs keep it. Two people who share every bound claim share a binding.
- Holder binding is separate: it ties a credential to a wallet key.

The `oid4vp-reference-credential-binding` provider selects the claims. The built-in `pid` provider reads its selection from the server configuration, because the login that issues a credential and the login that presents it share no other configuration. These are the defaults:

```properties
--spi-oid4vp-reference-credential-binding--pid--credential-types=urn:eudi:pid:1
--spi-oid4vp-reference-credential-binding--pid--claims=given_name,family_name,birthdate,personal_administrative_number
```

- **Credential types:** the VCT of an SD-JWT credential or the doctype of an mDoc. For the mDoc PID, configure `eu.europa.ec.eudi.pid.1` with the mDoc element names, for example `birth_date`.
- **Claim paths:** the same dot notation as the [IdP mappers](configuration.md#idp-mappers), for example `place_of_birth.locality` and `nationalities[]`. An mDoc path resolves inside the namespace of the credential.
- **Object and array claims:** read with ordered keys, so a different rendering by the wallet produces the same binding.
- **`personal_administrative_number`:** bound only when the PID carries it. If your PIDs omit it, name another claim that is unique to the person.
- **Empty `claims`:** Keycloak refuses this at startup. Binding everything would include issuance metadata, and a re-issued PID would break the binding.

When a bound claim changes, the verifier treats the credential as not presented. The user signs in with a password and Keycloak issues a credential bound to the current PID. Fewer claims make this rarer and the binding weaker. To bind to something other than a PID, write your own provider for this SPI.

A credential without a binding, such as one from another issuer, is accepted in any presentation. The exception is the credential that carries the subject: if it has no binding and sits next to credentials a binding would cover, Keycloak does not use it as the subject and fires the [`PRESENTATION_REFUSED`](events.md) event with reason `CREDENTIAL_IGNORED`.
