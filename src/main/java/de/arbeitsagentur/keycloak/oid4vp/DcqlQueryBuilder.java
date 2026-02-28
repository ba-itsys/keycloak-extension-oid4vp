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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

public class DcqlQueryBuilder {

    private static final Logger LOG = Logger.getLogger(DcqlQueryBuilder.class);

    public static final String PATH_SEPARATOR = "/";
    public static final String TYPE_KEY_DELIMITER = "|";

    private final ObjectMapper objectMapper;
    private final List<CredentialTypeSpec> credentialTypes = new ArrayList<>();
    private boolean allCredentialsRequired = false;
    private String purpose;

    public record ClaimSpec(String path, boolean optional) {
        public ClaimSpec(String path) {
            this(path, false);
        }
    }

    public record CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {
        public CredentialTypeSpec(String format, String type) {
            this(format, type, List.of());
        }

        public static CredentialTypeSpec fromPaths(String format, String type, List<String> claimPaths) {
            List<ClaimSpec> specs = claimPaths.stream().map(ClaimSpec::new).toList();
            return new CredentialTypeSpec(format, type, specs);
        }
    }

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        credentialTypes.add(new CredentialTypeSpec(format, type, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    public DcqlQueryBuilder addCredentialType(String format, String type) {
        return addCredentialType(format, type, List.of());
    }

    public DcqlQueryBuilder setAllCredentialsRequired(boolean required) {
        this.allCredentialsRequired = required;
        return this;
    }

    public DcqlQueryBuilder setPurpose(String purpose) {
        this.purpose = purpose;
        return this;
    }

    public String build() {
        if (credentialTypes.isEmpty()) {
            return buildDefaultDcql();
        }

        try {
            List<Map<String, Object>> credentials = new ArrayList<>();
            List<String> credentialIds = new ArrayList<>();
            int credIndex = 1;

            for (CredentialTypeSpec typeSpec : credentialTypes) {
                String credId = "cred" + credIndex++;
                credentialIds.add(credId);
                credentials.add(buildCredentialEntry(typeSpec, credId));
            }

            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put("credentials", credentials);

            if (credentials.size() > 1) {
                dcqlQuery.put("credential_sets", List.of(buildCredentialSet(credentialIds)));
            }

            return objectMapper.writeValueAsString(dcqlQuery);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build DCQL query", e);
        }
    }

    public static DcqlQueryBuilder fromMapperSpecs(
            ObjectMapper objectMapper,
            Map<String, CredentialTypeSpec> credentialTypes,
            boolean allCredentialsRequired,
            String purpose) {
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
        builder.setAllCredentialsRequired(allCredentialsRequired);
        builder.setPurpose(purpose);
        for (CredentialTypeSpec spec : credentialTypes.values()) {
            builder.credentialTypes.add(spec);
        }
        return builder;
    }

    static Map<String, CredentialTypeSpec> aggregateFromMappers(
            KeycloakSession session, Oid4vpIdentityProviderConfig config) {
        Map<String, CredentialTypeSpec> result = new LinkedHashMap<>();

        try {
            RealmModel realm = session.getContext().getRealm();
            if (realm == null) {
                return result;
            }

            String idpAlias = config.getAlias();
            Map<String, List<ClaimSpec>> claimsByType = new LinkedHashMap<>();
            Map<String, String> formatByType = new LinkedHashMap<>();

            realm.getIdentityProviderMappersByAliasStream(idpAlias).forEach(mapper -> {
                String format = mapper.getConfig().get("credential.format");
                String type = mapper.getConfig().get("credential.type");
                String claimPath = mapper.getConfig().get("claim");
                boolean isOptional = "true".equalsIgnoreCase(mapper.getConfig().get("optional"));

                if (StringUtil.isBlank(format)) {
                    format = Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC;
                }
                if (StringUtil.isBlank(type)) {
                    return;
                }

                String typeKey = format + TYPE_KEY_DELIMITER + type;
                formatByType.put(typeKey, format);

                if (StringUtil.isNotBlank(claimPath)) {
                    ClaimSpec claimSpec = new ClaimSpec(claimPath, isOptional);
                    claimsByType
                            .computeIfAbsent(typeKey, k -> new ArrayList<>())
                            .add(claimSpec);
                }
            });

            String sdJwtUserMappingClaim = config.getUserMappingClaim();
            String mdocUserMappingClaim = config.getUserMappingClaimMdoc();

            for (String typeKey : formatByType.keySet()) {
                String format = formatByType.get(typeKey);
                List<ClaimSpec> claims = claimsByType.computeIfAbsent(typeKey, k -> new ArrayList<>());

                String userMappingClaim = Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(format)
                        ? mdocUserMappingClaim
                        : sdJwtUserMappingClaim;

                if (StringUtil.isNotBlank(userMappingClaim)) {
                    boolean alreadyPresent =
                            claims.stream().anyMatch(spec -> spec.path().equals(userMappingClaim));
                    if (!alreadyPresent) {
                        claims.add(new ClaimSpec(userMappingClaim, false));
                    }
                }
            }

            for (Map.Entry<String, List<ClaimSpec>> entry : claimsByType.entrySet()) {
                String typeKey = entry.getKey();
                String[] keyParts = typeKey.split("\\" + TYPE_KEY_DELIMITER, 2);
                String format = formatByType.get(typeKey);
                String type = keyParts.length > 1 ? keyParts[1] : keyParts[0];
                result.put(typeKey, new CredentialTypeSpec(format, type, entry.getValue()));
            }
        } catch (Exception e) {
            LOG.warnf("Failed to aggregate mappers: %s", e.getMessage());
        }

        return result;
    }

    private Map<String, Object> buildCredentialEntry(CredentialTypeSpec typeSpec, String credId) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("id", credId);
        credential.put("format", typeSpec.format());
        credential.put("meta", buildMetaConstraint(typeSpec));

        if (!typeSpec.claimSpecs().isEmpty()) {
            addClaimsWithOptionalSets(credential, typeSpec.claimSpecs(), typeSpec.format(), typeSpec.type());
        }
        return credential;
    }

    private Map<String, Object> buildMetaConstraint(CredentialTypeSpec typeSpec) {
        Map<String, Object> meta = new LinkedHashMap<>();
        if (Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(typeSpec.format())) {
            meta.put("doctype_value", typeSpec.type());
        } else {
            meta.put("vct_values", List.of(typeSpec.type()));
        }
        return meta;
    }

    private void addClaimsWithOptionalSets(
            Map<String, Object> credential, List<ClaimSpec> claimSpecs, String format, String type) {
        List<Map<String, Object>> claims = new ArrayList<>();
        List<String> requiredClaimIds = new ArrayList<>();
        List<String> allClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;
        int claimIndex = 1;

        for (ClaimSpec claimSpec : claimSpecs) {
            String claimId = "claim" + claimIndex++;
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put("id", claimId);
            claim.put("path", splitClaimPath(claimSpec.path(), format, type));
            claims.add(claim);
            allClaimIds.add(claimId);
            if (claimSpec.optional()) {
                hasOptionalClaims = true;
            } else {
                requiredClaimIds.add(claimId);
            }
        }
        credential.put("claims", claims);

        if (hasOptionalClaims && !requiredClaimIds.isEmpty()) {
            credential.put("claim_sets", List.of(allClaimIds, requiredClaimIds));
        }
    }

    private Map<String, Object> buildCredentialSet(List<String> credentialIds) {
        Map<String, Object> credentialSet = new LinkedHashMap<>();
        if (StringUtil.isNotBlank(purpose)) {
            credentialSet.put("purpose", purpose);
        }

        if (allCredentialsRequired) {
            credentialSet.put("options", List.of(credentialIds));
        } else {
            List<List<String>> options = credentialIds.stream().map(List::of).toList();
            credentialSet.put("options", options);
        }
        return credentialSet;
    }

    private String buildDefaultDcql() {
        return "{\"credentials\":[{\"id\":\"cred1\",\"claims\":[{\"path\":[\"given_name\"]},{\"path\":[\"family_name\"]}]}]}";
    }

    static List<Object> splitClaimPath(String path, String format, String type) {
        if (StringUtil.isBlank(path)) {
            return List.of();
        }
        if (path.contains(PATH_SEPARATOR)) {
            return Arrays.stream(path.split(PATH_SEPARATOR))
                    .<Object>map(DcqlQueryBuilder::parsePathSegment)
                    .collect(Collectors.toList());
        }
        if (Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(format) && type != null) {
            return List.of(type, path);
        }
        return List.of(path);
    }

    private static Object parsePathSegment(String segment) {
        if ("null".equals(segment)) {
            return null;
        }
        try {
            int index = Integer.parseInt(segment);
            if (index >= 0) {
                return index;
            }
        } catch (NumberFormatException ignored) {
        }
        return segment;
    }
}
