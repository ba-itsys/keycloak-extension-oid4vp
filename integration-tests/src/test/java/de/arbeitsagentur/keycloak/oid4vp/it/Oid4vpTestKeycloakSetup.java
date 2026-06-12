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
package de.arbeitsagentur.keycloak.oid4vp.it;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public final class Oid4vpTestKeycloakSetup {

    public static final String IDP_ALIAS = "oid4vp";

    static final String DEFAULT_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
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

    private Oid4vpTestKeycloakSetup() {}

    // Default OID4VP identity provider used to provision the test realm
    public static IdentityProviderRepresentation defaultIdentityProvider(String trustListUrl, String x509CertPem) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(IDP_ALIAS);
        idp.setDisplayName("Sign in with Wallet");
        idp.setProviderId(Oid4vpConstants.PROVIDER_ID);
        idp.setEnabled(true);
        idp.setTrustEmail(false);
        idp.setStoreToken(false);
        idp.setAddReadTokenRoleOnCreate(false);
        idp.setAuthenticateByDefault(false);
        idp.setLinkOnly(false);
        idp.setFirstBrokerLoginFlowAlias("first broker login");

        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "not-used");
        config.put("clientSecret", "not-used");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, DEFAULT_DCQL_QUERY);
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, "family_name");
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, "eu.europa.ec.eudi.pid.1/family_name");
        config.put(Oid4vpIdentityProviderConfig.TRUST_LIST_URL, trustListUrl);
        config.put(Oid4vpIdentityProviderConfig.TRUSTED_AUTHORITIES_MODE, "none");
        config.put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "0");
        config.put(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, x509CertPem);
        config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, "true");
        idp.setConfig(config);
        return idp;
    }

    // Default identity provider mapper storing the credential's family name as a session note
    public static IdentityProviderMapperRepresentation defaultSessionNoteMapper() {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName("credential-family-name-session");
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-user-session-mapper");
        mapper.setConfig(Map.of(
                "claim", "family_name",
                "session.note", "credentialFamilyName",
                "optional", "false"));
        return mapper;
    }

    static void deleteAllOid4vpUsers(RealmResource realm) {
        for (UserRepresentation user : listOid4vpUsers(realm)) {
            realm.users().get(user.getId()).remove();
        }
    }

    static int countOid4vpUsers(RealmResource realm) {
        return listOid4vpUsers(realm).size();
    }

    private static List<UserRepresentation> listOid4vpUsers(RealmResource realm) {
        List<UserRepresentation> result = new ArrayList<>();
        for (UserRepresentation user : realm.users().list(0, 100)) {
            if ("admin".equals(user.getUsername()) || "test".equals(user.getUsername())) {
                continue;
            }
            try {
                List<FederatedIdentityRepresentation> identities =
                        realm.users().get(user.getId()).getFederatedIdentity();
                boolean hasOid4vp =
                        identities.stream().anyMatch(identity -> IDP_ALIAS.equals(identity.getIdentityProvider()));
                if (hasOid4vp) {
                    result.add(user);
                }
            } catch (Exception ignored) {
                // Users without federated identities are not OID4VP users.
            }
        }
        return result;
    }
}
