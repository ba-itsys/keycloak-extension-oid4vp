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
    Keycloak-->>Browser: Render login UI with openid4vp://...?client_id=...&request_uri=https://.../request-object/{request_handle}<br/>QR code for cross-device<br/>SSE URL=/cross-device/status?request_handle={request_handle}

    opt Cross-device browser waiting path
        Browser->>Keycloak: GET /cross-device/status?request_handle={request_handle}
        Note over Browser,Keycloak: Browser keeps one SSE connection open.<br/>The SSE service polls Keycloak's shared single-use-object store<br/>for oid4vp_complete:{request_handle} and emits a complete event when found.
    end

    Wallet->>Keycloak: GET /request-object/{request_handle}
    Keycloak-->>Wallet: Signed request object JWT

    opt Implementation also accepts wallet POST fetch
        Wallet->>Keycloak: POST /request-object/{request_handle}<br/>wallet_nonce and/or wallet_metadata
        Keycloak-->>Wallet: Signed request object JWT<br/>(optionally JWE-wrapped for the wallet key from wallet_metadata)
    end

    Wallet->>Keycloak: POST / with direct_post or direct_post.jwt
    Note over Keycloak: Verify vp_token, store deferred auth result,<br/>bind completion to the original browser auth session

    alt Same-device
        Keycloak-->>Wallet: JSON redirect_uri=https://.../complete-auth?request_handle={request_handle}
        Wallet->>Browser: Open absolute redirect_uri
        Browser->>Keycloak: GET /complete-auth?request_handle={request_handle}
    else Cross-device
        Keycloak-->>Wallet: 200 OK {}
        Keycloak-->>Browser: SSE event complete<br/>redirect_uri=https://.../complete-auth?request_handle={request_handle}
        Browser->>Keycloak: GET /complete-auth?request_handle={request_handle}
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
    Keycloak-->>Browser: openid4vp://...?client_id=...&request_uri=https://.../request-object/{request_handle}

    Note over Wallet,Keycloak: OID4VP authorization request by reference
    Wallet->>Keycloak: GET /request-object/{request_handle}
    Keycloak-->>Wallet: Request object JWT<br/>client_id, response_uri, response_mode, nonce, state, dcql_query, optional client_metadata

    opt Wallet POST fetch supported by implementation
        Wallet->>Keycloak: POST /request-object/{request_handle}<br/>wallet_nonce and/or wallet_metadata
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

    Note over Keycloak: Store deferred auth result for request_handle

    alt Same-device completion
        Keycloak-->>Wallet: redirect_uri=https://.../complete-auth?request_handle={request_handle}
    else Cross-device completion
        Browser->>Keycloak: GET /cross-device/status?request_handle={request_handle}
        Keycloak-->>Browser: SSE complete event with absolute redirect_uri after polling shared store
    end

    Browser->>Keycloak: GET /complete-auth?request_handle={request_handle}
    Keycloak-->>Browser: Keycloak authentication completes
```

For the full walkthrough, request/state lifecycle, and class-level responsibilities, see [Request Flow Walkthrough](request-flow.md).
