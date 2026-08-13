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
import de.arbeitsagentur.keycloak.oid4vp.mapper.AbstractOID4VPClaimMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserSessionAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserSessionAttributeMapper;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.utils.StringUtil;

/**
 * Builds DCQL (Digital Credentials Query Language) queries for OID4VP authorization requests.
 *
 * <p>DCQL queries specify which credential types and claims the verifier requires from the wallet.
 * This builder constructs the query from configured IdP mapper settings or programmatically added
 * credential types. Supports claim sets driven by per-mapper claim set ids, multi-credential sets,
 * and both SD-JWT VC and mDoc (ISO 18013-5) credential formats.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6 — DCQL Query</a>
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
     * Aggregates credential type specifications from the given OID4VP claim mappers. The mapper's
     * provider id determines the credential format; its configuration carries the credential type,
     * claim path, mDoc namespace, and claim set ids. Credential types are ordered by format and
     * type so the generated query does not depend on mapper enumeration order.
     */
    public static Map<String, CredentialTypeSpec> aggregateFromMappers(
            Stream<IdentityProviderMapperModel> mappers, Oid4vpConfigProvider config) {
        Map<String, CredentialTypeSpec> result = new LinkedHashMap<>();

        try {
            Map<CredentialTypeKey, List<ClaimSpec>> claimsByType = new LinkedHashMap<>();

            mappers.forEach(mapper -> {
                String format = formatOfMapper(mapper.getIdentityProviderMapper());
                if (format == null) {
                    return;
                }
                String type = mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE);
                String claimPath = mapper.getConfig().get(AbstractOID4VPClaimMapper.CLAIM);
                if (StringUtil.isBlank(type) || StringUtil.isBlank(claimPath)) {
                    return;
                }
                ClaimSpec claimSpec = claimSpecOfMapper(mapper, format, type.trim(), claimPath.trim());
                if (claimSpec.claimPath() == null) {
                    LOG.warnf("Ignoring invalid claim path '%s' of mapper %s", claimPath, mapper.getName());
                    return;
                }
                claimsByType
                        .computeIfAbsent(new CredentialTypeKey(format, type.trim()), k -> new ArrayList<>())
                        .add(claimSpec);
            });

            if (!config.isUseIdTokenSubject() && !config.isTransientUsersEnabled()) {
                for (Map.Entry<CredentialTypeKey, List<ClaimSpec>> entry : claimsByType.entrySet()) {
                    ClaimSpec principal = principalClaim(config, entry.getKey(), entry.getValue());
                    if (principal == null || principal.claimPath() == null) {
                        continue;
                    }
                    boolean alreadyPresent = entry.getValue().stream()
                            .anyMatch(spec -> spec.path().equals(principal.path())
                                    && Objects.equals(spec.namespace(), principal.namespace()));
                    if (!alreadyPresent) {
                        entry.getValue().add(principal);
                    }
                }
            }

            List<CredentialTypeKey> orderedKeys = claimsByType.keySet().stream()
                    .sorted(Comparator.comparing(CredentialTypeKey::format).thenComparing(CredentialTypeKey::type))
                    .toList();
            int credentialIndex = 1;
            for (CredentialTypeKey typeKey : orderedKeys) {
                result.put(
                        CREDENTIAL_ID_PREFIX + credentialIndex++,
                        new CredentialTypeSpec(typeKey.format(), typeKey.type(), claimsByType.get(typeKey)));
            }
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return result;
    }

    /** The DCQL credential format covered by the given mapper provider id, or null for other mappers. */
    private static String formatOfMapper(String mapperProviderId) {
        return switch (mapperProviderId) {
            case OID4VPSdJwtUserAttributeMapper.PROVIDER_ID, OID4VPSdJwtUserSessionAttributeMapper.PROVIDER_ID ->
                FORMAT_SD_JWT_VC;
            case OID4VPMdocUserAttributeMapper.PROVIDER_ID, OID4VPMdocUserSessionAttributeMapper.PROVIDER_ID ->
                FORMAT_MSO_MDOC;
            default -> null;
        };
    }

    private static ClaimSpec claimSpecOfMapper(
            IdentityProviderMapperModel mapper, String format, String type, String claimPath) {
        List<String> claimSetIds =
                ClaimSpec.parseClaimSetIds(mapper.getConfig().get(AbstractOID4VPClaimMapper.CLAIM_SET_IDS));
        if (FORMAT_MSO_MDOC.equals(format)) {
            String namespace = mapper.getConfig().get(OID4VPMdocUserAttributeMapper.NAMESPACE);
            String effectiveNamespace = StringUtil.isNotBlank(namespace) ? namespace.trim() : type;
            return ClaimSpec.mdoc(effectiveNamespace, claimPath, claimSetIds);
        }
        return ClaimSpec.sdJwt(claimPath, claimSetIds);
    }

    /**
     * The principal claim appended for a credential type so the subject is always requested. For
     * mDoc credentials the element is requested in the namespace the credential's own mappers use.
     */
    private static ClaimSpec principalClaim(
            Oid4vpConfigProvider config, CredentialTypeKey typeKey, List<ClaimSpec> claims) {
        String path = config.getPrincipalAttribute();
        if (StringUtil.isBlank(path)) {
            return null;
        }
        if (FORMAT_MSO_MDOC.equals(typeKey.format())) {
            String namespace = claims.isEmpty() ? typeKey.type() : claims.get(0).namespace();
            return ClaimSpec.mdoc(namespace, path);
        }
        return ClaimSpec.sdJwt(path);
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
            addClaims(credential, typeSpec);
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

    /**
     * Adds the credential's claims and, when any claim declares claim set ids, a {@code claim_sets}
     * entry with one option per distinct id, ordered lexicographically. The option order expresses
     * the verifier's preference; wallets use the first option they can satisfy. Claims without ids
     * are included in every option.
     */
    private void addClaims(Map<String, Object> credential, CredentialTypeSpec typeSpec) {
        List<ClaimSpec> claimSpecs = typeSpec.claimSpecs();
        List<Map<String, Object>> claims = new ArrayList<>();
        List<String> claimIds = new ArrayList<>();
        int claimIndex = 1;

        for (ClaimSpec claimSpec : claimSpecs) {
            String claimId = CLAIM_ID_PREFIX + claimIndex++;
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put(DCQL_ID, claimId);
            claim.put(DCQL_PATH, claimSpec.toDcqlPath());
            claims.add(claim);
            claimIds.add(claimId);
        }
        credential.put(DCQL_CLAIMS, claims);

        List<List<Integer>> options = typeSpec.claimSetOptionIndexes();
        if (options.isEmpty()) {
            return;
        }
        List<List<String>> claimSets = options.stream()
                .map(option -> option.stream().map(claimIds::get).toList())
                .toList();
        credential.put(DCQL_CLAIM_SETS, claimSets);
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
