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

    public static final String SD_JWT_PID_VCT = "urn:eudi:pid:1";
    public static final String MDOC_PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";

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
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, "family_name");
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, MDOC_PID_DOCTYPE + "/family_name");
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
                "session.note", "credentialFamilyName"));
        return mapper;
    }

    /**
     * Mappers that drive the auto-generated DCQL query: SD-JWT PID and mDoc PID with the claims
     * the wallet's default credentials carry. Credential set mode 'optional' (the default) lets
     * the wallet present either credential.
     */
    public static List<IdentityProviderMapperRepresentation> defaultDcqlMappers() {
        List<IdentityProviderMapperRepresentation> mappers = new ArrayList<>(sdJwtPidMappers());
        mappers.addAll(mdocPidMappers());
        return mappers;
    }

    public static List<IdentityProviderMapperRepresentation> sdJwtPidMappers() {
        return List.of(
                sessionNoteMapper(
                        "pid-sd-jwt-family-name", "dc+sd-jwt", SD_JWT_PID_VCT, "family_name", "sdJwtFamilyName"),
                sessionNoteMapper("pid-sd-jwt-given-name", "dc+sd-jwt", SD_JWT_PID_VCT, "given_name", "sdJwtGivenName"),
                sessionNoteMapper("pid-sd-jwt-birthdate", "dc+sd-jwt", SD_JWT_PID_VCT, "birthdate", "sdJwtBirthdate"));
    }

    public static List<IdentityProviderMapperRepresentation> mdocPidMappers() {
        return List.of(
                sessionNoteMapper(
                        "pid-mdoc-family-name",
                        "mso_mdoc",
                        MDOC_PID_DOCTYPE,
                        MDOC_PID_DOCTYPE + "/family_name",
                        "mdocFamilyName"),
                sessionNoteMapper(
                        "pid-mdoc-given-name",
                        "mso_mdoc",
                        MDOC_PID_DOCTYPE,
                        MDOC_PID_DOCTYPE + "/given_name",
                        "mdocGivenName"),
                sessionNoteMapper(
                        "pid-mdoc-birth-date",
                        "mso_mdoc",
                        MDOC_PID_DOCTYPE,
                        MDOC_PID_DOCTYPE + "/birth_date",
                        "mdocBirthDate"));
    }

    public static IdentityProviderMapperRepresentation sessionNoteMapper(
            String name, String format, String credentialType, String claim, String sessionNote) {
        return sessionNoteMapper(name, format, credentialType, claim, sessionNote, null);
    }

    public static IdentityProviderMapperRepresentation sessionNoteMapper(
            String name, String format, String credentialType, String claim, String sessionNote, String claimSetIds) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-user-session-mapper");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("credential.format", format);
        config.put("credential.type", credentialType);
        config.put("claim", claim);
        config.put("session.note", sessionNote);
        if (claimSetIds != null) {
            config.put("claimset.ids", claimSetIds);
        }
        mapper.setConfig(config);
        return mapper;
    }

    public static IdentityProviderMapperRepresentation attributeMapper(
            String name, String format, String credentialType, String claim, String userAttribute, String claimSetIds) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-user-attribute-mapper");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("syncMode", "INHERIT");
        config.put("credential.format", format);
        config.put("credential.type", credentialType);
        config.put("claim", claim);
        config.put("user.attribute", userAttribute);
        if (claimSetIds != null) {
            config.put("claimset.ids", claimSetIds);
        }
        mapper.setConfig(config);
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
