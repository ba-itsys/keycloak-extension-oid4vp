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
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialId;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.mapper.AbstractOID4VPClaimMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserSessionAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserSessionAttributeMapper;
import java.util.ArrayList;
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
    private static final String CLAIM_ID_PREFIX = "claim";

    private final ObjectMapper objectMapper;
    private final Map<String, CredentialTypeSpec> credentialTypes = new LinkedHashMap<>();
    private final Map<String, List<TrustedAuthority>> trustedAuthoritiesByCredentialId = new LinkedHashMap<>();
    private List<CredentialSet> credentialSets = List.of();

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** Adds a credential under the id derived from its format and type. */
    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        return addCredentialType(CredentialId.defaultFor(format, type), format, type, claimSpecs);
    }

    public DcqlQueryBuilder addCredentialType(
            String credentialId, String format, String type, List<ClaimSpec> claimSpecs) {
        credentialTypes.put(
                credentialId, new CredentialTypeSpec(format, type, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    /**
     * Sets the DCQL {@code credential_sets} constraints. Without them the query carries no
     * {@code credential_sets} member, which per DCQL means every credential is required.
     */
    public DcqlQueryBuilder setCredentialSets(List<CredentialSet> credentialSets) {
        this.credentialSets = credentialSets != null ? List.copyOf(credentialSets) : List.of();
        return this;
    }

    /**
     * Sets the {@code trusted_authorities} entries per credential id. They are not a verifier-wide
     * policy: each credential advertises what the trust material identity providers serving its
     * credential type expose, so a credential from a trusted list and one from a private trust
     * domain carry different entries.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1 — Trusted Authorities Query</a>
     */
    public DcqlQueryBuilder setTrustedAuthorities(
            Map<String, List<TrustedAuthority>> trustedAuthoritiesByCredentialId) {
        this.trustedAuthoritiesByCredentialId.clear();
        if (trustedAuthoritiesByCredentialId != null) {
            this.trustedAuthoritiesByCredentialId.putAll(trustedAuthoritiesByCredentialId);
        }
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
            for (Map.Entry<String, CredentialTypeSpec> credentialType : credentialTypes.entrySet()) {
                credentials.add(buildCredentialEntry(credentialType.getValue(), credentialType.getKey()));
            }

            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put(DCQL_CREDENTIALS, credentials);

            if (!credentialSets.isEmpty()) {
                dcqlQuery.put(
                        DCQL_CREDENTIAL_SETS,
                        credentialSets.stream()
                                .map(DcqlQueryBuilder::buildCredentialSet)
                                .toList());
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
            List<CredentialSet> credentialSets,
            Map<String, List<TrustedAuthority>> trustedAuthoritiesByCredentialId) {
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
        builder.setCredentialSets(credentialSets);
        builder.setTrustedAuthorities(trustedAuthoritiesByCredentialId);
        builder.credentialTypes.putAll(credentialTypes);
        return builder;
    }

    /**
     * Aggregates credential type specifications from the given OID4VP claim mappers, keyed by the
     * credential id the mappers resolve to. The mapper's provider id determines the credential
     * format; its configuration carries the credential type, credential id, claim path, mDoc
     * namespace, and claim set ids. Mappers sharing a credential id form one credential entry, so
     * the same credential type can be requested more than once with different claims. Credentials
     * are ordered by id so the generated query does not depend on mapper enumeration order.
     */
    public static AggregatedCredentials aggregateFromMappers(
            Stream<IdentityProviderMapperModel> mappers, Oid4vpConfigProvider config) {
        Map<String, CredentialTypeSpec> result = new LinkedHashMap<>();
        List<String> problems = new ArrayList<>();

        try {
            Map<String, CredentialTypeKey> typesByCredentialId = new LinkedHashMap<>();
            Map<String, List<ClaimSpec>> claimsByCredentialId = new LinkedHashMap<>();

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
                CredentialTypeKey typeKey = new CredentialTypeKey(format, type.trim());
                String credentialId = credentialIdOfMapper(mapper, typeKey);
                CredentialTypeKey known = typesByCredentialId.putIfAbsent(credentialId, typeKey);
                if (known != null && !known.equals(typeKey)) {
                    problems.add("mapper '" + mapper.getName() + "' uses the credential id '" + credentialId
                            + "' of credential type '" + known.type() + "' (format '" + known.format()
                            + "') for credential type '" + typeKey.type() + "' (format '" + typeKey.format()
                            + "'). A credential id addresses exactly one credential.");
                    return;
                }
                claimsByCredentialId
                        .computeIfAbsent(credentialId, k -> new ArrayList<>())
                        .add(claimSpec);
            });

            if (!config.isTransientUsersEnabled()) {
                // With a subject credential configured the principal claim is requested from that
                // credential alone. Without one the subject comes from whichever credential the
                // wallet presents, so every credential has to carry it.
                String subjectCredentialId = config.getPrincipalCredentialId();
                for (Map.Entry<String, List<ClaimSpec>> entry : claimsByCredentialId.entrySet()) {
                    if (StringUtil.isNotBlank(subjectCredentialId) && !subjectCredentialId.equals(entry.getKey())) {
                        continue;
                    }
                    ClaimSpec principal =
                            principalClaim(config, typesByCredentialId.get(entry.getKey()), entry.getValue());
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

            claimsByCredentialId.keySet().stream().sorted().forEach(credentialId -> {
                CredentialTypeKey typeKey = typesByCredentialId.get(credentialId);
                result.put(
                        credentialId,
                        new CredentialTypeSpec(
                                typeKey.format(), typeKey.type(), claimsByCredentialId.get(credentialId)));
            });
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return new AggregatedCredentials(result, List.copyOf(problems));
    }

    /**
     * The credentials the mappers request, keyed by credential id, together with the configuration
     * problems found while aggregating them.
     */
    public record AggregatedCredentials(Map<String, CredentialTypeSpec> credentials, List<String> problems) {}

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

        List<Map<String, Object>> trustedAuthorities =
                TrustedAuthority.toDcqlEntries(trustedAuthoritiesByCredentialId.getOrDefault(credId, List.of()));
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

    private static Map<String, Object> buildCredentialSet(CredentialSet configuredSet) {
        Map<String, Object> credentialSet = new LinkedHashMap<>();
        if (StringUtil.isNotBlank(configuredSet.purpose())) {
            credentialSet.put(DCQL_PURPOSE, configuredSet.purpose());
        }
        credentialSet.put(DCQL_OPTIONS, configuredSet.options());
        // DCQL defaults required to true, so it is only written when the set is optional.
        if (!configuredSet.required()) {
            credentialSet.put(DCQL_REQUIRED, false);
        }
        return credentialSet;
    }

    /** The credential id a mapper contributes to: its explicit id, or the one derived from format and type. */
    private static String credentialIdOfMapper(IdentityProviderMapperModel mapper, CredentialTypeKey typeKey) {
        String configured = mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_ID);
        if (StringUtil.isBlank(configured)) {
            return CredentialId.defaultFor(typeKey.format(), typeKey.type());
        }
        String credentialId = configured.trim();
        if (!CredentialId.isValid(credentialId)) {
            LOG.warnf(
                    "Mapper %s configures the invalid credential id '%s'; falling back to the derived id",
                    mapper.getName(), credentialId);
            return CredentialId.defaultFor(typeKey.format(), typeKey.type());
        }
        return credentialId;
    }

    private record CredentialTypeKey(String format, String type) {}
}
