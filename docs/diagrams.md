# OID4VP Diagrams

These diagrams summarize the browser, wallet, and Keycloak verifier flow at two levels:

- a high-level interaction view for same-device and cross-device login
- a lower-level protocol view showing where OID4VP, trust-list validation, and status-list checks fit

## High-Level Interaction

```mermaid
sequenceDiagram
    autonumber
    actor Browser
    participant Keycloak as Keycloak verifier
    participant Wallet

    Browser->>Keycloak: Open Keycloak login page
    Keycloak-->>Browser: Render login UI with openid4vp://...?client_id=...&request_uri=https://.../request-object/{state}<br/>QR code for cross-device<br/>SSE URL=/cross-device/status?state={state}

    opt Cross-device browser waiting path
        Browser->>Keycloak: GET /cross-device/status?state={state}
        Note over Browser,Keycloak: Browser keeps one SSE connection open.<br/>A virtual-thread SSE worker polls Keycloak's shared single-use-object store<br/>for oid4vp_complete:{state} and emits a complete event when found.
    end

    Wallet->>Keycloak: GET /request-object/{state}
    Keycloak-->>Wallet: Signed request object JWT

    opt Implementation also accepts wallet POST fetch
        Wallet->>Keycloak: POST /request-object/{state}<br/>wallet_nonce and/or wallet_metadata
        Keycloak-->>Wallet: Signed request object JWT<br/>(optionally JWE-wrapped for the wallet key from wallet_metadata)
    end

    Wallet->>Keycloak: POST / with direct_post or direct_post.jwt
    Note over Keycloak: Verify vp_token, store deferred auth result,<br/>generate single-use response_code,<br/>bind completion to the original browser auth session

    alt Same-device
        Keycloak-->>Wallet: JSON redirect_uri=https://.../complete-auth?state={state}&response_code={response_code}
        Wallet->>Browser: Open absolute redirect_uri
        Browser->>Keycloak: GET /complete-auth?state={state}&response_code={response_code}
    else Cross-device
        Keycloak-->>Wallet: 200 OK {}
        Keycloak-->>Browser: SSE event complete<br/>redirect_uri=https://.../complete-auth?state={state}&response_code={response_code}
        Browser->>Keycloak: GET /complete-auth?state={state}&response_code={response_code}
    end

    Keycloak-->>Browser: Resume Keycloak login flow / first broker login
```

## Protocol Mapping

```mermaid
sequenceDiagram
    autonumber
    actor Browser
    participant Wallet
    participant Keycloak as Keycloak verifier
    participant TrustList as ETSI trust list
    participant StatusList as Token status list
    participant IssuerMeta as JWT VC issuer metadata (optional)

    Note over Browser,Keycloak: Keycloak browser login step
    Browser->>Keycloak: GET broker login page
    Keycloak-->>Browser: openid4vp://...?client_id=...&request_uri=https://.../request-object/{state}

    Note over Wallet,Keycloak: OID4VP authorization request by reference
    Wallet->>Keycloak: GET /request-object/{state}
    Keycloak-->>Wallet: Request object JWT<br/>client_id, response_uri, response_mode, nonce, state, dcql_query, optional client_metadata

    opt Wallet POST fetch supported by implementation
        Wallet->>Keycloak: POST /request-object/{state}<br/>wallet_nonce and/or wallet_metadata
        Keycloak-->>Wallet: Request object JWT or nested JWE
    end

    Note over Wallet,Keycloak: OID4VP response_mode direct_post / direct_post.jwt
    Wallet->>Keycloak: POST / with direct_post or direct_post.jwt

    Note over Keycloak: VP validation and claim extraction
    Note over Keycloak: SD-JWT VC: issuer signature + KB-JWT checks<br/>mDoc: issuer signature + device authentication checks

    Note over Keycloak,TrustList: Trust-chain validation
    Keycloak->>TrustList: GET trustListUrl
    TrustList-->>Keycloak: ETSI TS 119 602 trust list JWT
    Note over Keycloak: Used for x5c / mDoc issuer trust and for status-list signer trust

    opt Outside HAIP and no usable x5c chain
        Keycloak->>IssuerMeta: GET /.well-known/jwt-vc-issuer and optional jwks_uri
        IssuerMeta-->>Keycloak: Issuer metadata / JWKS
    end

    Note over Keycloak,StatusList: Revocation check
    Keycloak->>StatusList: GET credential status.status_list.uri
    StatusList-->>Keycloak: Status list token
    Note over Keycloak: Decode bitstring, read idx, reject revoked credentials

    Note over Keycloak: Store deferred auth result for state,<br/>generate single-use response_code

    alt Same-device completion
        Keycloak-->>Wallet: redirect_uri=https://.../complete-auth?state={state}&response_code={response_code}
    else Cross-device completion
        Browser->>Keycloak: GET /cross-device/status?state={state}
        Keycloak-->>Browser: SSE complete event with absolute redirect_uri (incl. response_code) after polling shared store
    end

    Browser->>Keycloak: GET /complete-auth?state={state}&response_code={response_code}
    Keycloak-->>Browser: Keycloak verifies response_code, authentication completes
```

For the full walkthrough, request/state lifecycle, and class-level responsibilities, see [Request Flow Walkthrough](request-flow.md).
