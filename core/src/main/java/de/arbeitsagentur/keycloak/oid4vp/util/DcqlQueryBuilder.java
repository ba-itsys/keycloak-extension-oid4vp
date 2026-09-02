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
import de.arbeitsagentur.keycloak.oid4vp.domain.DcqlId;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.PrincipalAttribute;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.mapper.AbstractOID4VPClaimMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPMdocUserSessionAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserAttributeMapper;
import de.arbeitsagentur.keycloak.oid4vp.mapper.OID4VPSdJwtUserSessionAttributeMapper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.utils.StringUtil;

/**
 * Builds the DCQL (Digital Credentials Query Language) query that tells the wallet which credential
 * types and claims the verifier requires, for both the SD-JWT VC and the mDoc (ISO 18013-5) format.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6, DCQL Query</a>
 */
public class DcqlQueryBuilder {

    private static final Logger LOG = Logger.getLogger(DcqlQueryBuilder.class);
    private static final String CLAIM_ID_PREFIX = "claim";
    private static final String CLAIM_ID_COLLISION_SEPARATOR = "-";
    private static final String PRINCIPAL_CLAIM_ID = "principal";

    private final ObjectMapper objectMapper;
    private final Map<String, CredentialTypeSpec> credentialTypes = new LinkedHashMap<>();
    private final Map<String, List<TrustedAuthority>> trustedAuthoritiesByCredentialId = new LinkedHashMap<>();
    private List<CredentialSet> credentialSets = List.of();

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        return addCredentialType(CredentialId.defaultFor(format, type), format, type, claimSpecs);
    }

    public DcqlQueryBuilder addCredentialType(
            String credentialId, String format, String type, List<ClaimSpec> claimSpecs) {
        return addCredentialType(credentialId, format, List.of(type), claimSpecs);
    }

    public DcqlQueryBuilder addCredentialType(
            String credentialId, String format, List<String> types, List<ClaimSpec> claimSpecs) {
        credentialTypes.put(
                credentialId, new CredentialTypeSpec(format, types, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    /**
     * Sets the DCQL {@code credential_sets} constraints. Leaving them empty writes no
     * {@code credential_sets} member, which per DCQL makes every credential required.
     */
    public DcqlQueryBuilder setCredentialSets(List<CredentialSet> credentialSets) {
        this.credentialSets = credentialSets != null ? List.copyOf(credentialSets) : List.of();
        return this;
    }

    /**
     * Sets the {@code trusted_authorities} entries per credential id. They are not a verifier wide
     * policy: each credential advertises only what the trust material identity providers serving
     * its credential type expose, so a credential from a trusted list and one from a private trust
     * domain carry different entries.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1, Trusted Authorities Query</a>
     */
    public DcqlQueryBuilder setTrustedAuthorities(
            Map<String, List<TrustedAuthority>> trustedAuthoritiesByCredentialId) {
        this.trustedAuthoritiesByCredentialId.clear();
        if (trustedAuthoritiesByCredentialId != null) {
            this.trustedAuthoritiesByCredentialId.putAll(trustedAuthoritiesByCredentialId);
        }
        return this;
    }

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
     * Aggregates the credential entries from the OID4VP claim mappers, keyed by credential id.
     * Mappers sharing a credential id form a single entry that accepts every type any of them
     * names, while an mDoc entry is limited to one doctype because DCQL takes a single
     * {@code doctype_value}. Entries are sorted by id so that the resulting query does not depend
     * on the order in which the realm returns the mappers.
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
                List<String> types = CredentialTypeSpec.parseTypes(
                        mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_TYPE));
                String claimPath = mapper.getConfig().get(AbstractOID4VPClaimMapper.CLAIM);
                if (types.isEmpty() || StringUtil.isBlank(claimPath)) {
                    return;
                }
                if (FORMAT_MSO_MDOC.equals(format) && types.size() > 1) {
                    problems.add("mapper '" + mapper.getName() + "' names the doctypes " + types
                            + ", but an mDoc credential entry accepts one doctype (DCQL doctype_value is a"
                            + " single string). Request each doctype under its own credential id.");
                    return;
                }
                ClaimSpec claimSpec = claimSpecOfMapper(mapper, format, types.get(0), claimPath.trim());
                if (!claimSpec.pathsWellFormed()) {
                    LOG.warnf(
                            "Ignoring mapper %s: invalid claim path among '%s' and the alternatives %s",
                            mapper.getName(), claimPath, claimSpec.alternativePaths());
                    return;
                }
                CredentialTypeKey typeKey = new CredentialTypeKey(format, types);
                String credentialId = credentialIdOfMapper(mapper, typeKey);
                CredentialTypeKey known = typesByCredentialId.putIfAbsent(credentialId, typeKey);
                if (known != null) {
                    if (!known.format().equals(format)) {
                        problems.add("mapper '" + mapper.getName() + "' uses the credential id '" + credentialId
                                + "' of format '" + known.format() + "' for format '" + format
                                + "'. A credential id addresses credentials of one format.");
                        return;
                    }
                    if (FORMAT_MSO_MDOC.equals(format) && !known.types().equals(types)) {
                        problems.add("mapper '" + mapper.getName() + "' uses the credential id '" + credentialId
                                + "' of doctype '" + known.firstType() + "' for doctype '" + types.get(0)
                                + "'. An mDoc credential id addresses exactly one doctype.");
                        return;
                    }
                    typesByCredentialId.put(credentialId, known.withTypes(types));
                }
                claimsByCredentialId
                        .computeIfAbsent(credentialId, k -> new ArrayList<>())
                        .add(claimSpec);
            });

            if (!config.isTransientUsersEnabled()) {
                // The claim carrying the subject is requested from the credentials named as
                // principal attributes. Each credential is asked for the claim it was named with.
                // A credential that never answers for the subject is not asked for it.
                Map<String, PrincipalAttribute> principalByCredentialId = new LinkedHashMap<>();
                config.getPrincipalAttributes()
                        .forEach(principal -> principalByCredentialId.put(principal.credentialId(), principal));
                for (Map.Entry<String, List<ClaimSpec>> entry : claimsByCredentialId.entrySet()) {
                    if (!principalByCredentialId.containsKey(entry.getKey())) {
                        continue;
                    }
                    ClaimSpec principal = principalClaim(
                            principalByCredentialId.get(entry.getKey()), typesByCredentialId.get(entry.getKey()));
                    if (principal == null || principal.claimPath() == null) {
                        continue;
                    }
                    boolean alreadyPresent = entry.getValue().stream()
                            .anyMatch(spec -> spec.path().equals(principal.path())
                                    && Objects.equals(spec.namespace(), principal.namespace()));
                    if (!alreadyPresent) {
                        entry.getValue().add(principal.withId(PRINCIPAL_CLAIM_ID));
                    }
                }
            }

            claimsByCredentialId.keySet().stream().sorted().forEach(credentialId -> {
                CredentialTypeKey typeKey = typesByCredentialId.get(credentialId);
                result.put(
                        credentialId,
                        new CredentialTypeSpec(
                                typeKey.format(), typeKey.types(), claimsByCredentialId.get(credentialId)));
            });
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return new AggregatedCredentials(result, List.copyOf(problems));
    }

    public record AggregatedCredentials(Map<String, CredentialTypeSpec> credentials, List<String> problems) {}

    private static String formatOfMapper(String mapperProviderId) {
        return switch (mapperProviderId) {
            case OID4VPSdJwtUserAttributeMapper.PROVIDER_ID, OID4VPSdJwtUserSessionAttributeMapper.PROVIDER_ID ->
                FORMAT_SD_JWT_VC;
            case OID4VPMdocUserAttributeMapper.PROVIDER_ID, OID4VPMdocUserSessionAttributeMapper.PROVIDER_ID ->
                FORMAT_MSO_MDOC;
            default -> null;
        };
    }

    /**
     * Builds the claim of one mapper, giving it the slugged mapper name as its id so that the generated
     * {@code claim_sets} read like the configuration an admin sees.
     */
    private static ClaimSpec claimSpecOfMapper(
            IdentityProviderMapperModel mapper, String format, String type, String claimPath) {
        List<String> claimSetIds =
                ClaimSpec.parseClaimSetIds(mapper.getConfig().get(AbstractOID4VPClaimMapper.CLAIM_SET_IDS));
        List<String> alternativePaths =
                ClaimSpec.parseAlternativePaths(mapper.getConfig().get(AbstractOID4VPClaimMapper.CLAIM_ALTERNATIVES))
                        .stream()
                        .filter(alternative -> !alternative.equals(claimPath))
                        .toList();
        ClaimSpec claimSpec;
        if (FORMAT_MSO_MDOC.equals(format)) {
            String namespace = mapper.getConfig().get(OID4VPMdocUserAttributeMapper.NAMESPACE);
            String effectiveNamespace = StringUtil.isNotBlank(namespace) ? namespace.trim() : type;
            claimSpec = ClaimSpec.mdoc(effectiveNamespace, claimPath, claimSetIds);
        } else {
            claimSpec = ClaimSpec.sdJwt(claimPath, claimSetIds);
        }
        return claimSpec.withId(claimIdOfMapper(mapper)).withAlternativePaths(alternativePaths);
    }

    private static String claimIdOfMapper(IdentityProviderMapperModel mapper) {
        String name = mapper.getName();
        return StringUtil.isBlank(name) ? null : DcqlId.slug(name.trim());
    }

    /**
     * Builds the claim that requests the subject of one credential. The configured path starts at
     * the root of the presentation, so for an mDoc its first step is the namespace, which DCQL asks
     * for separately.
     */
    private static ClaimSpec principalClaim(PrincipalAttribute principal, CredentialTypeKey typeKey) {
        if (principal == null) {
            return null;
        }
        if (!FORMAT_MSO_MDOC.equals(typeKey.format())) {
            return ClaimSpec.sdJwt(principal.claimPath());
        }
        String namespace = principal.mdocNamespace();
        if (namespace == null) {
            // Without a namespace the path cannot address a data element of an mDoc.
            return null;
        }
        return ClaimSpec.mdoc(namespace, principal.mdocElementPath());
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
            meta.put(DCQL_DOCTYPE_VALUE, typeSpec.firstType());
        } else {
            meta.put(DCQL_VCT_VALUES, typeSpec.types());
        }
        return meta;
    }

    /**
     * Adds the claims, along with the {@code claim_sets} options whenever a claim carries claim set
     * ids or alternatives. The option order expresses the verifier's preference, since a wallet
     * takes the first option it can satisfy.
     *
     * <p>Claims are keyed by their DCQL path because a query may point to a claim only once (OID4VP
     * 1.0 §6.1), so mappers reading the same claim share one entry under the id of the first of
     * them. mDoc mappers reading different parts of one data element share an entry as well,
     * because an mDoc path stops at the element.
     */
    private void addClaims(Map<String, Object> credential, CredentialTypeSpec typeSpec) {
        List<ClaimSpec> requestedClaims = typeSpec.requestedClaims();
        List<Map<String, Object>> claims = new ArrayList<>();
        List<String> claimIdsByRequestedClaim = new ArrayList<>();
        Map<List<Object>, String> claimIdsByPointer = new LinkedHashMap<>();
        Set<String> usedClaimIds = new HashSet<>();
        int unnamedClaimIndex = 1;

        for (ClaimSpec claimSpec : requestedClaims) {
            List<Object> pointer = claimSpec.toDcqlPath();
            String claimId = claimIdsByPointer.get(pointer);
            if (claimId == null) {
                String preferredId = claimSpec.id() != null ? claimSpec.id() : CLAIM_ID_PREFIX + unnamedClaimIndex++;
                claimId = uniqueClaimId(preferredId, usedClaimIds);
                usedClaimIds.add(claimId);
                claimIdsByPointer.put(pointer, claimId);
                Map<String, Object> claim = new LinkedHashMap<>();
                claim.put(DCQL_ID, claimId);
                claim.put(DCQL_PATH, pointer);
                claims.add(claim);
            }
            claimIdsByRequestedClaim.add(claimId);
        }
        credential.put(DCQL_CLAIMS, claims);

        List<List<Integer>> options = typeSpec.claimSetOptionIndexes();
        if (options.isEmpty()) {
            return;
        }
        List<List<String>> claimSets = options.stream()
                .map(option -> option.stream()
                        .map(claimIdsByRequestedClaim::get)
                        .distinct()
                        .toList())
                .distinct()
                .toList();
        credential.put(DCQL_CLAIM_SETS, claimSets);
    }

    private static String uniqueClaimId(String preferredId, Set<String> usedClaimIds) {
        String claimId = preferredId;
        for (int suffix = 2; usedClaimIds.contains(claimId); suffix++) {
            claimId = preferredId + CLAIM_ID_COLLISION_SEPARATOR + suffix;
        }
        return claimId;
    }

    private static Map<String, Object> buildCredentialSet(CredentialSet configuredSet) {
        Map<String, Object> credentialSet = new LinkedHashMap<>();
        if (StringUtil.isNotBlank(configuredSet.purpose())) {
            credentialSet.put(DCQL_PURPOSE, configuredSet.purpose());
        }
        credentialSet.put(DCQL_OPTIONS, configuredSet.options());
        // DCQL defaults required to true, so it only needs writing when the set is optional.
        if (!configuredSet.required()) {
            credentialSet.put(DCQL_REQUIRED, false);
        }
        return credentialSet;
    }

    /** Resolves the credential id a mapper contributes to, falling back to one derived from format and first type. */
    private static String credentialIdOfMapper(IdentityProviderMapperModel mapper, CredentialTypeKey typeKey) {
        String configured = mapper.getConfig().get(AbstractOID4VPClaimMapper.CREDENTIAL_ID);
        if (StringUtil.isNotBlank(configured) && !CredentialId.isValid(configured.trim())) {
            LOG.warnf(
                    "Mapper %s configures the invalid credential id '%s'; falling back to the derived id",
                    mapper.getName(), configured.trim());
        }
        return CredentialId.resolve(configured, typeKey.format(), typeKey.firstType());
    }

    private record CredentialTypeKey(String format, List<String> types) {

        String firstType() {
            return types.get(0);
        }

        CredentialTypeKey withTypes(List<String> moreTypes) {
            List<String> merged = new ArrayList<>(types);
            moreTypes.stream().filter(type -> !merged.contains(type)).forEach(merged::add);
            return new CredentialTypeKey(format, merged);
        }
    }
}
