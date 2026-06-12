/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.oid4vp.domain;

import java.net.URI;
import java.util.List;

/**
 * Protocol constants for the OID4VP 1.0 identity provider extension.
 *
 * <p>Contains parameter names, response modes, credential format identifiers, client ID scheme
 * values, and endpoint flow constants used throughout the OID4VP authorization flow as defined in
 * <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</a>.
 */
public final class Oid4vpConstants {

    private Oid4vpConstants() {}

    /** Builds the base URL for the IdP endpoint: {@code {baseUri}/realms/{realm}/broker/{alias}/endpoint}. */
    public static String buildEndpointBaseUrl(URI baseUri, String realmName, String idpAlias) {
        String base = baseUri.toString();
        if (!base.endsWith("/")) {
            base += "/";
        }
        return base + "realms/" + realmName + "/broker/" + idpAlias + "/endpoint";
    }

    public static final String PROVIDER_ID = "oid4vp";

    // Credential formats
    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";

    // JOSE signature algorithms
    public static final String JWS_ALG_ES256 = "ES256";
    public static final String JWS_ALG_ES384 = "ES384";
    public static final String JWS_ALG_ES512 = "ES512";
    public static final String JWS_ALG_RS256 = "RS256";

    // COSE signature algorithms
    public static final int COSE_ALG_ES256 = -7;
    public static final int COSE_ALG_ES384 = -35;
    public static final int COSE_ALG_ES512 = -36;

    public static final List<String> SUPPORTED_SD_JWT_ALG_VALUES =
            List.of(JWS_ALG_ES256, JWS_ALG_ES384, JWS_ALG_ES512, JWS_ALG_RS256);
    public static final List<Integer> SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES =
            List.of(COSE_ALG_ES256, COSE_ALG_ES384, COSE_ALG_ES512);
    public static final List<Integer> SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES = SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES;
    public static final List<String> SUPPORTED_VERIFIER_RESPONSE_ENCRYPTION_METHOD_VALUES =
            List.of("A128GCM", "A256GCM");
    public static final List<String> SUPPORTED_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS = List.of("ECDH-ES");
    public static final List<String> SUPPORTED_REQUEST_OBJECT_ENCRYPTION_METHODS = List.of("A128GCM", "A256GCM");

    // OID4VP protocol parameters
    public static final String VP_TOKEN = "vp_token";
    public static final String REQUEST_URI = "request_uri";
    public static final String DCQL_QUERY = "dcql_query";
    public static final String CLIENT_METADATA = "client_metadata";
    public static final String VERIFIER_INFO = "verifier_info";
    public static final String WALLET_NONCE = "wallet_nonce";
    public static final String WALLET_METADATA = "wallet_metadata";
    public static final String RESPONSE_URI = "response_uri";
    public static final String RESPONSE = "response";
    public static final String DCQL_CREDENTIALS = "credentials";
    public static final String DCQL_CREDENTIAL_SETS = "credential_sets";
    public static final String DCQL_CLAIMS = "claims";
    public static final String DCQL_CLAIM_SETS = "claim_sets";
    public static final String DCQL_OPTIONS = "options";
    public static final String DCQL_PURPOSE = "purpose";
    public static final String DCQL_FORMAT = "format";
    public static final String DCQL_ID = "id";
    public static final String DCQL_META = "meta";
    public static final String DCQL_PATH = "path";
    public static final String DCQL_TRUSTED_AUTHORITIES = "trusted_authorities";
    public static final String DCQL_TRUSTED_AUTHORITY_TYPE = "type";
    public static final String DCQL_TRUSTED_AUTHORITY_VALUES = "values";
    public static final String DCQL_TRUSTED_AUTHORITY_ETSI_TL = "etsi_tl";
    public static final String DCQL_TRUSTED_AUTHORITY_AKI = "aki";
    public static final String DCQL_VCT_VALUES = "vct_values";
    public static final String DCQL_DOCTYPE_VALUE = "doctype_value";

    // Response mode values
    public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
    public static final String RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt";

    // Response type values
    public static final String RESPONSE_TYPE_VP_TOKEN_ID_TOKEN = "vp_token id_token";

    // ID Token parameter
    public static final String ID_TOKEN = "id_token";

    // Self-Issued OpenID Provider v2 static identifier
    // https://openid.net/specs/openid-connect-self-issued-v2-1_0-ID1.html#name-static-self-issued-openid-p
    public static final String SELF_ISSUED_V2 = "https://self-issued.me/v2";

    // Flow types
    public static final String FLOW_SAME_DEVICE = "same_device";
    public static final String FLOW_CROSS_DEVICE = "cross_device";

    // Query/form parameter names
    public static final String PARAM_TAB_ID = "tab_id";
    public static final String PARAM_SESSION_CODE = "session_code";
    public static final String PARAM_CLIENT_DATA = "client_data";
    public static final String PARAM_REQUEST_HANDLE = "request_handle";

    // Request object media type
    public static final String REQUEST_OBJECT_CONTENT_TYPE = "application/oauth-authz-req+jwt";
    public static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    // Default wallet scheme
    public static final String DEFAULT_WALLET_SCHEME = "openid4vp://";
}
