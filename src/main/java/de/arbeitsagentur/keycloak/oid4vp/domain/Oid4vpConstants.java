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

public final class Oid4vpConstants {

    private Oid4vpConstants() {}

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

    // OID4VP protocol parameters
    public static final String VP_TOKEN = "vp_token";
    public static final String REQUEST_URI = "request_uri";
    public static final String DCQL_QUERY = "dcql_query";
    public static final String CLIENT_METADATA = "client_metadata";
    public static final String VERIFIER_INFO = "verifier_info";
    public static final String WALLET_NONCE = "wallet_nonce";
    public static final String RESPONSE_URI = "response_uri";
    public static final String RESPONSE = "response";

    // Response mode values
    public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
    public static final String RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt";

    // Response type values
    public static final String RESPONSE_TYPE_VP_TOKEN = "vp_token";

    // Self-issued audience
    public static final String SELF_ISSUED_V2 = "https://self-issued.me/v2";

    // Flow types
    public static final String FLOW_SAME_DEVICE = "same_device";
    public static final String FLOW_CROSS_DEVICE = "cross_device";
    public static final String FLOW_PARAM = "flow";

    // Query/form parameter names
    public static final String PARAM_TAB_ID = "tab_id";
    public static final String PARAM_SESSION_CODE = "session_code";
    public static final String PARAM_CLIENT_DATA = "client_data";
    public static final String PARAM_TOKEN = "token";
    public static final String PARAM_REQUEST_HANDLE = "request_handle";

    // Request object media type
    public static final String REQUEST_OBJECT_CONTENT_TYPE = "application/oauth-authz-req+jwt";
    public static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

    // Client ID scheme values
    public static final String CLIENT_ID_SCHEME_X509_SAN_DNS = "x509_san_dns";
    public static final String CLIENT_ID_SCHEME_X509_HASH = "x509_hash";
    public static final String CLIENT_ID_SCHEME_PLAIN = "plain";

    // Default wallet scheme
    public static final String DEFAULT_WALLET_SCHEME = "openid4vp://";

    // Session/auth note keys
    public static final String SESSION_STATE = "oid4vp_state";
    public static final String SESSION_NONCE = "oid4vp_nonce";
    public static final String SESSION_RESPONSE_URI = "oid4vp_response_uri";
    public static final String SESSION_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    public static final String SESSION_ENCRYPTION_KEY = "oid4vp_encryption_key";
    public static final String SESSION_CLIENT_ID = "oid4vp_client_id";
    public static final String SESSION_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";
    public static final String SESSION_MDOC_GENERATED_NONCE = "oid4vp_mdoc_generated_nonce";
}
