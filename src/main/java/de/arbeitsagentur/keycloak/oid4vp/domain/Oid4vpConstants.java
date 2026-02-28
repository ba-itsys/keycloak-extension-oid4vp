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

public final class Oid4vpConstants {

    private Oid4vpConstants() {}

    public static final String PROVIDER_ID = "oid4vp";

    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";

    public static final String SESSION_STATE = "oid4vp_state";
    public static final String SESSION_NONCE = "oid4vp_nonce";
    public static final String SESSION_RESPONSE_URI = "oid4vp_response_uri";
    public static final String SESSION_REDIRECT_FLOW_RESPONSE_URI = "oid4vp_redirect_flow_response_uri";
    public static final String SESSION_ENCRYPTION_KEY = "oid4vp_encryption_key";
    public static final String SESSION_CLIENT_ID = "oid4vp_client_id";
    public static final String SESSION_EFFECTIVE_CLIENT_ID = "oid4vp_effective_client_id";
    public static final String SESSION_MDOC_GENERATED_NONCE = "oid4vp_mdoc_generated_nonce";
    public static final String SESSION_TAB_ID = "oid4vp_tab_id";
    public static final String SESSION_CLIENT_DATA = "oid4vp_client_data";
    public static final String SESSION_CODE = "oid4vp_session_code";
}
