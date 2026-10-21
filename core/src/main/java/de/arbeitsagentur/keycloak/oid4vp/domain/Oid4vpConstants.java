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
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jwe.JWEConstants;

/**
 * Protocol constants of the OID4VP 1.0 identity provider extension. Parameter names, response
 * modes, credential formats, client id scheme values and flow constants come from
 * <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</a>.
 */
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

    public static final String FORMAT_MSO_MDOC = "mso_mdoc";

    // COSE algorithm values of RFC 9053 section 2.1
    public static final int COSE_ALG_ES256 = -7;
    public static final int COSE_ALG_ES384 = -35;
    public static final int COSE_ALG_ES512 = -36;

    public static final List<String> SUPPORTED_SD_JWT_ALG_VALUES =
            List.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512, Algorithm.RS256);
    public static final List<Integer> SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES =
            List.of(COSE_ALG_ES256, COSE_ALG_ES384, COSE_ALG_ES512);
    public static final List<Integer> SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES = SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES;
    public static final List<String> SUPPORTED_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS = List.of(JWEConstants.ECDH_ES);
    public static final List<String> SUPPORTED_REQUEST_OBJECT_ENCRYPTION_METHODS =
            List.of(JWEConstants.A128GCM, JWEConstants.A256GCM);

    public static final String REQUEST_URI = "request_uri";
    public static final String REQUEST_URI_METHOD = "request_uri_method";
    public static final String REQUEST_URI_METHOD_POST = "post";
    public static final String DCQL_QUERY = "dcql_query";
    public static final String CLIENT_METADATA = "client_metadata";
    public static final String VERIFIER_INFO = "verifier_info";
    public static final String WALLET_NONCE = "wallet_nonce";
    public static final String WALLET_METADATA = "wallet_metadata";
    public static final String RESPONSE_URI = "response_uri";
    public static final String DCQL_CREDENTIALS = "credentials";
    public static final String DCQL_CREDENTIAL_SETS = "credential_sets";
    public static final String DCQL_CLAIMS = "claims";
    public static final String DCQL_CLAIM_SETS = "claim_sets";
    public static final String DCQL_OPTIONS = "options";
    public static final String DCQL_REQUIRED = "required";
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

    public static final String FLOW_SAME_DEVICE = "same_device";
    public static final String FLOW_CROSS_DEVICE = "cross_device";

    public static final String PARAM_TAB_ID = "tab_id";

    public static final String DEFAULT_WALLET_SCHEME = "openid4vp://";
}
