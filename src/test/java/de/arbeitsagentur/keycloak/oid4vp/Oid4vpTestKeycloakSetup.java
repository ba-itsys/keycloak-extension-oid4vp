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
package de.arbeitsagentur.keycloak.oid4vp;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

final class Oid4vpTestKeycloakSetup {

    static final String DEFAULT_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:1"] },
                  "claims": [
                    { "path": ["family_name"] },
                    { "path": ["given_name"] },
                    { "path": ["birthdate"] }
                  ]
                },
                {
                  "id": "pid_mdoc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                  "claims": [
                    { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                  ]
                }
              ],
              "credential_sets": [
                {
                  "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                  "required": true
                }
              ]
            }
            """;

    static void addRedirectUriToClient(KeycloakAdminClient admin, String realm, String clientId, String redirectUri)
            throws Exception {
        List<Map<String, Object>> clients =
                admin.getJsonList("/admin/realms/" + realm + "/clients?clientId=" + urlEncode(clientId));
        Map<String, Object> client = clients.stream()
                .filter(entry -> clientId.equals(entry.get("clientId")))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        String id = String.valueOf(client.get("id"));

        Map<String, Object> rep = admin.getJson("/admin/realms/" + realm + "/clients/" + id);
        Object raw = rep.get("redirectUris");
        List<String> redirectUris = raw instanceof List<?> list
                ? list.stream().map(String::valueOf).distinct().collect(Collectors.toCollection(ArrayList::new))
                : new ArrayList<>();
        if (!redirectUris.contains(redirectUri)) {
            redirectUris.add(redirectUri);
        }
        rep.put("redirectUris", redirectUris);
        admin.putJson("/admin/realms/" + realm + "/clients/" + id, rep);
    }

    static void configureOid4vpIdentityProvider(KeycloakAdminClient admin, String realm) throws Exception {
        Map<String, Object> idpConfig = new LinkedHashMap<>();
        idpConfig.put("alias", "oid4vp");
        idpConfig.put("displayName", "Sign in with Wallet");
        idpConfig.put("providerId", Oid4vpIdentityProviderFactory.PROVIDER_ID);
        idpConfig.put("enabled", true);
        idpConfig.put("trustEmail", false);
        idpConfig.put("storeToken", false);
        idpConfig.put("addReadTokenRoleOnCreate", false);
        idpConfig.put("authenticateByDefault", false);
        idpConfig.put("linkOnly", false);
        idpConfig.put("firstBrokerLoginFlowAlias", "first broker login");

        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "not-used");
        config.put("clientSecret", "not-used");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, DEFAULT_DCQL_QUERY);
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, "family_name");
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, "eu.europa.ec.eudi.pid.1/family_name");
        config.put(Oid4vpIdentityProviderConfig.SKIP_TRUST_LIST_VERIFICATION, "true");
        config.put(Oid4vpIdentityProviderConfig.TRUST_X5C_FROM_CREDENTIAL, "true");
        idpConfig.put("config", config);

        admin.deleteIfExists("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        admin.postJson("/admin/realms/" + realm + "/identity-provider/instances", idpConfig);

        Map<String, Object> realmRep = admin.getJson("/admin/realms/" + realm);
        realmRep.put("loginTheme", "oid4vp");
        admin.putJson("/admin/realms/" + realm, realmRep);
    }

    static void configureDcqlQuery(KeycloakAdminClient admin, String realm, String dcqlQuery) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, dcqlQuery);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    static void configureSameDeviceFlow(KeycloakAdminClient admin, String realm, boolean enabled) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, String.valueOf(enabled));
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    static void configureCrossDeviceFlow(KeycloakAdminClient admin, String realm, boolean enabled) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, String.valueOf(enabled));
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    static void deleteAllOid4vpUsers(KeycloakAdminClient admin, String realm) throws Exception {
        List<Map<String, Object>> users = admin.getJsonList("/admin/realms/" + realm + "/users?max=100");
        for (Map<String, Object> user : users) {
            String userId = String.valueOf(user.get("id"));
            String username = String.valueOf(user.get("username"));
            if ("admin".equals(username) || "test".equals(username)) continue;
            try {
                List<Map<String, Object>> identities =
                        admin.getJsonList("/admin/realms/" + realm + "/users/" + userId + "/federated-identity");
                boolean hasOid4vp = identities.stream().anyMatch(id -> "oid4vp".equals(id.get("identityProvider")));
                if (hasOid4vp) {
                    admin.delete("/admin/realms/" + realm + "/users/" + userId);
                }
            } catch (Exception ignored) {
            }
        }
    }

    static void setIdpConfig(KeycloakAdminClient admin, String realm, String key, String value) throws Exception {
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        @SuppressWarnings("unchecked")
        Map<String, String> config = (Map<String, String>) idp.get("config");
        config.put(key, value);
        admin.putJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp", idp);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Oid4vpTestKeycloakSetup() {}
}
