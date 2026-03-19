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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

/**
 * Builds DCQL (Digital Credentials Query Language) queries for OID4VP authorization requests.
 *
 * <p>DCQL queries specify which credential types and claims the verifier requires from the wallet.
 * This builder can either construct a query from configured IdP mapper settings (auto-generated)
 * or be used programmatically. Supports optional/required claims, multi-credential sets, and
 * both SD-JWT VC and mDoc (ISO 18013-5) credential formats.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.4">OID4VP 1.0 §5.4 — DCQL Query</a>
 */
public class DcqlQueryBuilder {

    private static final Logger LOG = Logger.getLogger(DcqlQueryBuilder.class);
    private static final String CREDENTIAL_ID_PREFIX = "cred";
    private static final String CLAIM_ID_PREFIX = "claim";

    private final ObjectMapper objectMapper;
    private final List<CredentialTypeSpec> credentialTypes = new ArrayList<>();
    private boolean allCredentialsRequired = false;
    private String purpose;
    private Oid4vpTrustedAuthoritiesMode trustedAuthoritiesMode = Oid4vpTrustedAuthoritiesMode.NONE;
    private String trustedAuthoritiesTrustListUrl;
    private List<String> trustedAuthoritiesAuthorityKeyIdentifiers = List.of();

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        credentialTypes.add(new CredentialTypeSpec(format, type, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    public DcqlQueryBuilder setAllCredentialsRequired(boolean required) {
        this.allCredentialsRequired = required;
        return this;
    }

    public DcqlQueryBuilder setPurpose(String purpose) {
        this.purpose = purpose;
        return this;
    }

    /**
     * Sets the ETSI Trusted List URL to include as a {@code trusted_authorities} constraint
     * on each credential entry. When set, each credential in the DCQL query will contain
     * {@code "trusted_authorities": [{"type": "etsi_tl", "values": ["<url>"]}]}.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1 — Trusted Authorities Query</a>
     */
    public DcqlQueryBuilder setTrustListUrl(String trustListUrl) {
        this.trustedAuthoritiesMode = Oid4vpTrustedAuthoritiesMode.ETSI_TL;
        this.trustedAuthoritiesTrustListUrl = trustListUrl;
        this.trustedAuthoritiesAuthorityKeyIdentifiers = List.of();
        return this;
    }

    public DcqlQueryBuilder setTrustedAuthorities(String trustListUrl, List<String> authorityKeyIdentifiers) {
        this.trustedAuthoritiesMode = Oid4vpTrustedAuthoritiesMode.AKI;
        this.trustedAuthoritiesTrustListUrl = trustListUrl;
        this.trustedAuthoritiesAuthorityKeyIdentifiers =
                authorityKeyIdentifiers != null ? List.copyOf(authorityKeyIdentifiers) : List.of();
        return this;
    }

    public DcqlQueryBuilder setTrustedAuthoritiesMode(
            Oid4vpTrustedAuthoritiesMode mode, String trustListUrl, List<String> authorityKeyIdentifiers) {
        this.trustedAuthoritiesMode = mode != null ? mode : Oid4vpTrustedAuthoritiesMode.NONE;
        this.trustedAuthoritiesTrustListUrl = trustListUrl;
        this.trustedAuthoritiesAuthorityKeyIdentifiers =
                authorityKeyIdentifiers != null ? List.copyOf(authorityKeyIdentifiers) : List.of();
        return this;
    }

    /** Builds the DCQL query JSON string from the configured credential types and claims. */
    public String build() {
        if (credentialTypes.isEmpty()) {
            throw new IllegalStateException(
                    "No credential types configured. Add at least one credential type to the DCQL query.");
        }

        try {
            List<Map<String, Object>> credentials = new ArrayList<>();
            List<String> credentialIds = new ArrayList<>();
            int credIndex = 1;

            for (CredentialTypeSpec typeSpec : credentialTypes) {
                String credId = CREDENTIAL_ID_PREFIX + credIndex++;
                credentialIds.add(credId);
                credentials.add(buildCredentialEntry(typeSpec, credId));
            }

            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put(DCQL_CREDENTIALS, credentials);

            if (credentials.size() > 1) {
                dcqlQuery.put(DCQL_CREDENTIAL_SETS, List.of(buildCredentialSet(credentialIds)));
            }

            return objectMapper.writeValueAsString(dcqlQuery);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build DCQL query", e);
        }
    }

    /** Normalizes a manually supplied DCQL query to include inferred metadata and trust constraints. */
    public static String normalizeManualQuery(ObjectMapper objectMapper, String dcqlQuery, String trustListUrl) {
        return normalizeManualQuery(
                objectMapper, dcqlQuery, Oid4vpTrustedAuthoritiesMode.ETSI_TL, trustListUrl, List.of());
    }

    public static String normalizeManualQuery(
            ObjectMapper objectMapper,
            String dcqlQuery,
            Oid4vpTrustedAuthoritiesMode trustedAuthoritiesMode,
            String trustListUrl,
            List<String> authorityKeyIdentifiers) {
        if (StringUtil.isBlank(dcqlQuery)) {
            return dcqlQuery;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(dcqlQuery, Map.class);
            normalizeParsedQuery(parsed, trustedAuthoritiesMode, trustListUrl, authorityKeyIdentifiers);
            return objectMapper.writeValueAsString(parsed);
        } catch (Exception e) {
            LOG.warnf("Failed to normalize manual DCQL query: %s", e.getMessage());
            return dcqlQuery;
        }
    }

    /** Mutates a parsed DCQL query map so manual queries match auto-generated metadata behavior. */
    @SuppressWarnings("unchecked")
    public static void normalizeParsedQuery(
            Map<?, ?> dcqlQuery,
            Oid4vpTrustedAuthoritiesMode trustedAuthoritiesMode,
            String trustListUrl,
            List<String> authorityKeyIdentifiers) {
        Object credentialsObj = dcqlQuery.get(DCQL_CREDENTIALS);
        if (!(credentialsObj instanceof List<?> credentials)) {
            return;
        }
        List<Map<String, Object>> trustedAuthorities =
                trustedAuthoritiesMode.toDcqlEntries(trustListUrl, authorityKeyIdentifiers);

        for (Object credentialObj : credentials) {
            if (!(credentialObj instanceof Map<?, ?> rawCredential)) {
                continue;
            }

            Object formatObj = rawCredential.get(DCQL_FORMAT);
            Object idObj = rawCredential.get(DCQL_ID);
            if (!(formatObj instanceof String format)
                    || !(idObj instanceof String credentialType)
                    || StringUtil.isBlank(credentialType)) {
                continue;
            }

            Map<String, Object> credential = (Map<String, Object>) rawCredential;
            Map<String, Object> meta = ensureMetaConstraint(credential, format, credentialType);
            if (meta != null && FORMAT_SD_JWT_VC.equals(format) && !meta.containsKey(DCQL_VCT_VALUES)) {
                meta.put(DCQL_VCT_VALUES, List.of(credentialType));
            } else if (meta != null && FORMAT_MSO_MDOC.equals(format) && !meta.containsKey(DCQL_DOCTYPE_VALUE)) {
                meta.put(DCQL_DOCTYPE_VALUE, credentialType);
            }

            if (!trustedAuthorities.isEmpty() && !credential.containsKey(DCQL_TRUSTED_AUTHORITIES)) {
                credential.put(DCQL_TRUSTED_AUTHORITIES, trustedAuthorities);
            }
        }
    }

    /** Creates a builder pre-populated from aggregated mapper credential type specifications. */
    public static DcqlQueryBuilder fromMapperSpecs(
            ObjectMapper objectMapper,
            Map<String, CredentialTypeSpec> credentialTypes,
            boolean allCredentialsRequired,
            String purpose,
            String trustListUrl) {
        return fromMapperSpecs(
                objectMapper,
                credentialTypes,
                allCredentialsRequired,
                purpose,
                Oid4vpTrustedAuthoritiesMode.ETSI_TL,
                trustListUrl,
                List.of());
    }

    public static DcqlQueryBuilder fromMapperSpecs(
            ObjectMapper objectMapper,
            Map<String, CredentialTypeSpec> credentialTypes,
            boolean allCredentialsRequired,
            String purpose,
            Oid4vpTrustedAuthoritiesMode trustedAuthoritiesMode,
            String trustListUrl,
            List<String> authorityKeyIdentifiers) {
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
        builder.setAllCredentialsRequired(allCredentialsRequired);
        builder.setPurpose(purpose);
        builder.setTrustedAuthoritiesMode(trustedAuthoritiesMode, trustListUrl, authorityKeyIdentifiers);
        builder.credentialTypes.addAll(credentialTypes.values());
        return builder;
    }

    /**
     * Aggregates credential type specifications from all IdP mappers configured for this provider.
     * Scans mapper configurations for credential format, type, and claim paths, then groups them
     * into {@link CredentialTypeSpec} entries suitable for DCQL query generation.
     */
    public static Map<String, CredentialTypeSpec> aggregateFromMappers(
            KeycloakSession session, Oid4vpConfigProvider config) {
        Map<String, CredentialTypeSpec> result = new LinkedHashMap<>();

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                return result;
            }

            String idpAlias = config.getAlias();
            Map<CredentialTypeKey, CredentialTypeKey> credentialTypesByKey = new LinkedHashMap<>();
            Map<CredentialTypeKey, List<ClaimSpec>> claimsByType = new LinkedHashMap<>();

            realm.getIdentityProviderMappersByAliasStream(idpAlias).forEach(mapper -> {
                String format = mapper.getConfig().get(Oid4vpMapperConfigProperties.CREDENTIAL_FORMAT);
                String type = mapper.getConfig().get(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE);
                String claimPath = mapper.getConfig().get(Oid4vpMapperConfigProperties.CLAIM_PATH);
                boolean isOptional =
                        "true".equalsIgnoreCase(mapper.getConfig().get(Oid4vpMapperConfigProperties.OPTIONAL));
                boolean isMultivalued =
                        "true".equalsIgnoreCase(mapper.getConfig().get(Oid4vpMapperConfigProperties.MULTIVALUED));

                if (StringUtil.isBlank(format)) {
                    format = FORMAT_SD_JWT_VC;
                }
                if (StringUtil.isBlank(type)) {
                    return;
                }

                CredentialTypeKey typeKey = new CredentialTypeKey(format, type);
                credentialTypesByKey.put(typeKey, typeKey);

                if (StringUtil.isNotBlank(claimPath)) {
                    ClaimSpec claimSpec = new ClaimSpec(claimPath, isOptional, isMultivalued);
                    claimsByType
                            .computeIfAbsent(typeKey, k -> new ArrayList<>())
                            .add(claimSpec);
                }
            });

            if (!config.isUseIdTokenSubject() && !config.isTransientUsersEnabled()) {
                String sdJwtUserMappingClaim = config.getUserMappingClaim();
                String mdocUserMappingClaim = config.getUserMappingClaimMdoc();

                for (CredentialTypeKey typeKey : credentialTypesByKey.keySet()) {
                    String format = typeKey.format();
                    List<ClaimSpec> claims = claimsByType.computeIfAbsent(typeKey, k -> new ArrayList<>());

                    String userMappingClaim =
                            FORMAT_MSO_MDOC.equals(format) ? mdocUserMappingClaim : sdJwtUserMappingClaim;

                    if (StringUtil.isNotBlank(userMappingClaim)) {
                        boolean alreadyPresent =
                                claims.stream().anyMatch(spec -> spec.path().equals(userMappingClaim));
                        if (!alreadyPresent) {
                            claims.add(new ClaimSpec(userMappingClaim, false));
                        }
                    }
                }
            }

            int credentialIndex = 1;
            for (CredentialTypeKey typeKey : credentialTypesByKey.keySet()) {
                List<ClaimSpec> claims = claimsByType.getOrDefault(typeKey, List.of());
                result.put(
                        CREDENTIAL_ID_PREFIX + credentialIndex++,
                        new CredentialTypeSpec(typeKey.format(), typeKey.type(), claims));
            }
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return result;
    }

    private Map<String, Object> buildCredentialEntry(CredentialTypeSpec typeSpec, String credId) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put(DCQL_ID, credId);
        credential.put(DCQL_FORMAT, typeSpec.format());
        credential.put(DCQL_META, buildMetaConstraint(typeSpec));

        List<Map<String, Object>> trustedAuthorities = trustedAuthoritiesMode.toDcqlEntries(
                trustedAuthoritiesTrustListUrl, trustedAuthoritiesAuthorityKeyIdentifiers);
        if (!trustedAuthorities.isEmpty()) {
            credential.put(DCQL_TRUSTED_AUTHORITIES, trustedAuthorities);
        }

        if (!typeSpec.claimSpecs().isEmpty()) {
            addClaimsWithOptionalSets(credential, typeSpec.claimSpecs(), typeSpec.format(), typeSpec.type());
        }
        return credential;
    }

    private Map<String, Object> buildMetaConstraint(CredentialTypeSpec typeSpec) {
        Map<String, Object> meta = new LinkedHashMap<>();
        if (FORMAT_MSO_MDOC.equals(typeSpec.format())) {
            meta.put(DCQL_DOCTYPE_VALUE, typeSpec.type());
        } else {
            meta.put(DCQL_VCT_VALUES, List.of(typeSpec.type()));
        }
        return meta;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ensureMetaConstraint(
            Map<String, Object> credential, String format, String credentialType) {
        Object metaObj = credential.get(DCQL_META);
        if (metaObj instanceof Map<?, ?> rawMeta) {
            return (Map<String, Object>) rawMeta;
        }
        if (FORMAT_SD_JWT_VC.equals(format) || FORMAT_MSO_MDOC.equals(format)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            credential.put(DCQL_META, meta);
            return meta;
        }
        return null;
    }

    private void addClaimsWithOptionalSets(
            Map<String, Object> credential, List<ClaimSpec> claimSpecs, String format, String type) {
        List<Map<String, Object>> claims = new ArrayList<>();
        List<String> requiredClaimIds = new ArrayList<>();
        List<String> allClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;
        int claimIndex = 1;

        for (ClaimSpec claimSpec : claimSpecs) {
            String claimId = CLAIM_ID_PREFIX + claimIndex++;
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put(DCQL_ID, claimId);
            claim.put(DCQL_PATH, claimSpec.toDcqlPath(format, type));
            claims.add(claim);
            allClaimIds.add(claimId);
            if (claimSpec.optional()) {
                hasOptionalClaims = true;
            } else {
                requiredClaimIds.add(claimId);
            }
        }
        credential.put(DCQL_CLAIMS, claims);

        if (hasOptionalClaims && !requiredClaimIds.isEmpty()) {
            credential.put(DCQL_CLAIM_SETS, List.of(allClaimIds, requiredClaimIds));
        }
    }

    private Map<String, Object> buildCredentialSet(List<String> credentialIds) {
        Map<String, Object> credentialSet = new LinkedHashMap<>();
        if (StringUtil.isNotBlank(purpose)) {
            credentialSet.put(DCQL_PURPOSE, purpose);
        }

        if (allCredentialsRequired) {
            credentialSet.put(DCQL_OPTIONS, List.of(credentialIds));
        } else {
            List<List<String>> options = credentialIds.stream().map(List::of).toList();
            credentialSet.put(DCQL_OPTIONS, options);
        }
        return credentialSet;
    }

    private record CredentialTypeKey(String format, String type) {}
}
