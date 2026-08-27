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
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialId;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.mapper.AbstractOID4VPClaimMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPEidasLoaUserSessionAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserSessionAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.models.IdentityProviderMapperSyncMode;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public final class Oid4vpTestKeycloakSetup {

    public static final String IDP_ALIAS = "oid4vp";
    public static final String TRUST_IDP_ALIAS = "etsi-trust-list";

    public static final String SD_JWT_PID_VCT = "urn:eudi:pid:1";
    public static final String MDOC_PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";
    public static final String SD_JWT_PID_CREDENTIAL_ID =
            CredentialId.defaultFor(Oid4vpConstants.FORMAT_SD_JWT_VC, SD_JWT_PID_VCT);
    public static final String MDOC_PID_CREDENTIAL_ID =
            CredentialId.defaultFor(Oid4vpConstants.FORMAT_MSO_MDOC, MDOC_PID_DOCTYPE);

    private Oid4vpTestKeycloakSetup() {}

    // Default ETSI trust list identity provider serving the wallet's trust list
    public static IdentityProviderRepresentation defaultTrustListIdentityProvider(String trustListUrl) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(TRUST_IDP_ALIAS);
        idp.setDisplayName("ETSI Trust List");
        idp.setProviderId(EtsiTrustListIdentityProviderFactory.PROVIDER_ID);
        idp.setEnabled(true);

        Map<String, String> config = new LinkedHashMap<>();
        config.put(EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL, trustListUrl);
        // Nothing is advertised by default, so most tests drive the wallet without a
        // trusted_authorities constraint. The tests that cover it configure the advertised type.
        idp.setConfig(config);
        return idp;
    }

    // Default OID4VP identity provider used to provision the test realm
    public static IdentityProviderRepresentation defaultIdentityProvider(String x509CertPem) {
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
        config.put(Oid4vpIdentityProviderConfig.TRUST_MATERIAL_IDPS, TRUST_IDP_ALIAS);
        config.put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "0");
        config.put(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, x509CertPem);
        config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, "true");
        config.put(
                Oid4vpIdentityProviderConfig.CREDENTIAL_SETS,
                alternativeCredentialSets(SD_JWT_PID_CREDENTIAL_ID, MDOC_PID_CREDENTIAL_ID));
        // The PID answers in either format, so both are named and both read the same claim
        config.put(Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES, defaultPrincipalAttributeIds());
        idp.setConfig(config);
        return idp;
    }

    /**
     * The subject read from whichever format of the PID a wallet answers with. An mDoc path names
     * the namespace before the element, so the dots of the doctype namespace are escaped.
     */
    public static String defaultPrincipalAttributeIds() {
        return principalAttributesFor(SD_JWT_PID_CREDENTIAL_ID, MDOC_PID_CREDENTIAL_ID);
    }

    /** The principal credential entries for the given credential ids, reading 'family_name'. */
    public static String principalAttributesFor(String... credentialIds) {
        return Arrays.stream(credentialIds)
                .map(credentialId -> credentialId + ":" + principalClaimPathOf(credentialId))
                .collect(Collectors.joining(", "));
    }

    /** The path 'family_name' resolves under, from the root of what the credential presents. */
    private static String principalClaimPathOf(String credentialId) {
        return MDOC_PID_CREDENTIAL_ID.equals(credentialId)
                ? MDOC_PID_DOCTYPE.replace(".", "\\.") + ".family_name"
                : "family_name";
    }

    /** A credential set that accepts any one of the given credentials, each as its own option. */
    public static String alternativeCredentialSets(String... credentialIds) {
        String options = Arrays.stream(credentialIds)
                .map(credentialId -> "[\"" + credentialId + "\"]")
                .collect(Collectors.joining(", "));
        return "[{\"options\": [" + options + "]}]";
    }

    /** The distinct credential ids the given mappers contribute to, in query order. */
    public static List<String> credentialIdsOf(List<IdentityProviderMapperRepresentation> mappers) {
        return mappers.stream()
                .map(Oid4vpTestKeycloakSetup::credentialIdOf)
                .distinct()
                .sorted()
                .toList();
    }

    private static String credentialIdOf(IdentityProviderMapperRepresentation mapper) {
        String configured = mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_ID);
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        return CredentialId.defaultFor(
                formatOf(mapper), mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE));
    }

    private static String formatOf(IdentityProviderMapperRepresentation mapper) {
        String providerId = mapper.getIdentityProviderMapper();
        boolean mdoc = OID4VPMdocUserSessionAttributeMapper.PROVIDER_ID.equals(providerId)
                || OID4VPMdocUserAttributeMapper.PROVIDER_ID.equals(providerId);
        return mdoc ? Oid4vpConstants.FORMAT_MSO_MDOC : Oid4vpConstants.FORMAT_SD_JWT_VC;
    }

    // Maps how the presentation finished to the mapper's default STORK QAA level, stored as a
    // session note under its default attribute name. Sync mode FORCE, so the note is also set
    // when a first wallet login links an existing account.
    public static IdentityProviderMapperRepresentation eidasLoaMapper() {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName("eidas-loa");
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper(OID4VPEidasLoaUserSessionAttributeMapper.PROVIDER_ID);
        mapper.setConfig(Map.of("syncMode", IdentityProviderMapperSyncMode.FORCE.name()));
        return mapper;
    }

    // Default identity provider mapper storing the credential's family name as a session note.
    // No credential type: it applies to any presented SD-JWT credential.
    public static IdentityProviderMapperRepresentation defaultSessionNoteMapper() {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName("credential-family-name-session");
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-sd-jwt-user-session-attribute-idp-mapper");
        mapper.setConfig(Map.of(
                "claim", "family_name",
                "attribute", "credentialFamilyName"));
        return mapper;
    }

    /**
     * Mappers that drive the auto-generated DCQL query: SD-JWT PID and mDoc PID with the claims
     * the wallet's default credentials carry. The credential sets configured on the identity
     * provider let the wallet present either credential.
     */
    public static List<IdentityProviderMapperRepresentation> defaultDcqlMappers() {
        List<IdentityProviderMapperRepresentation> mappers = new ArrayList<>(sdJwtPidMappers());
        mappers.addAll(mdocPidMappers());
        return mappers;
    }

    public static List<IdentityProviderMapperRepresentation> sdJwtPidMappers() {
        return List.of(
                sdJwtSessionMapper("pid-sd-jwt-family-name", SD_JWT_PID_VCT, "family_name", "sdJwtFamilyName", null),
                sdJwtSessionMapper("pid-sd-jwt-given-name", SD_JWT_PID_VCT, "given_name", "sdJwtGivenName", null),
                sdJwtSessionMapper("pid-sd-jwt-birthdate", SD_JWT_PID_VCT, "birthdate", "sdJwtBirthdate", null));
    }

    public static List<IdentityProviderMapperRepresentation> mdocPidMappers() {
        return List.of(
                mdocSessionMapper("pid-mdoc-family-name", MDOC_PID_DOCTYPE, "family_name", "mdocFamilyName"),
                mdocSessionMapper("pid-mdoc-given-name", MDOC_PID_DOCTYPE, "given_name", "mdocGivenName"),
                mdocSessionMapper("pid-mdoc-birth-date", MDOC_PID_DOCTYPE, "birth_date", "mdocBirthDate"));
    }

    public static IdentityProviderMapperRepresentation sdJwtSessionMapper(
            String name, String vct, String claim, String attribute, String claimSetIds) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-sd-jwt-user-session-attribute-idp-mapper");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("credential.type", vct);
        config.put("claim", claim);
        config.put("attribute", attribute);
        if (claimSetIds != null) {
            config.put("claimset.ids", claimSetIds);
        }
        mapper.setConfig(config);
        return mapper;
    }

    // The namespace is omitted: the PID namespace equals the doctype, which is the default.
    public static IdentityProviderMapperRepresentation mdocSessionMapper(
            String name, String doctype, String element, String attribute) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-mdoc-user-session-attribute-idp-mapper");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("credential.type", doctype);
        config.put("claim", element);
        config.put("attribute", attribute);
        mapper.setConfig(config);
        return mapper;
    }

    public static IdentityProviderMapperRepresentation sdJwtAttributeMapper(
            String name, String vct, String claim, String userAttribute, String claimSetIds) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IDP_ALIAS);
        mapper.setIdentityProviderMapper("oid4vp-sd-jwt-user-attribute-idp-mapper");
        Map<String, String> config = new LinkedHashMap<>();
        config.put("syncMode", "INHERIT");
        config.put("credential.type", vct);
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
            List<FederatedIdentityRepresentation> identities =
                    realm.users().get(user.getId()).getFederatedIdentity();
            boolean hasOid4vp =
                    identities.stream().anyMatch(identity -> IDP_ALIAS.equals(identity.getIdentityProvider()));
            if (hasOid4vp) {
                result.add(user);
            }
        }
        return result;
    }
}
