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
package de.arbeitsagentur.keycloak.oid4vp.mapper;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Base for OID4VP identity provider mappers that read a claim of the verified credential
 * presentation, addressed by a {@link ClaimPath} over the claims JSON. Subclasses decide where the
 * resolved values go and which credential format they cover. Every mapper also declares its
 * credential type and optionally its DCQL claim sets, since the mappers drive the generated DCQL
 * query.
 *
 * <p>Kept in sync with upstream Keycloak's {@code AbstractOID4VPClaimMapper}.
 */
public abstract class AbstractOID4VPClaimMapper extends AbstractIdentityProviderMapper {

    protected static final Logger logger = Logger.getLogger(AbstractOID4VPClaimMapper.class);

    public static final String CLAIM = "claim";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CLAIM_SET_IDS = "claimset.ids";

    private static final String[] COMPATIBLE_PROVIDERS = {Oid4vpConstants.PROVIDER_ID};

    protected static ProviderConfigProperty claimProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CLAIM);
        property.setLabel("Claim");
        property.setHelpText("Path of the claim in the presented credential. Use dot notation for nested claims, "
                + "i.e. 'address.locality', [] to select all array elements, i.e. 'nationalities[]', and [0] to select the first element of the presented array. "
                + "To use dot (.) literally, escape it with backslash (\\.)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        return property;
    }

    protected static ProviderConfigProperty credentialTypeProperty(String helpText) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CREDENTIAL_TYPE);
        property.setLabel("Credential Type");
        property.setHelpText(helpText);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        return property;
    }

    protected static ProviderConfigProperty claimSetIdsProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CLAIM_SET_IDS);
        property.setLabel("Claim Set IDs");
        property.setHelpText("Comma-separated claim set identifiers. When any claim of the same credential defines "
                + "claim set ids, the generated DCQL query contains one claim_sets option per id, ordered "
                + "lexicographically by id. Claims without ids are part of every option and are always requested. "
                + "Leave empty to always request this claim.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        return property;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    /** The credential format this mapper covers, as used in DCQL queries. */
    public abstract String credentialFormat();

    /** Whether the presented credential matches this mapper's format and configured type. */
    protected boolean matchesCredential(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String presentedFormat = (String) context.getContextData().get(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_FORMAT_KEY);
        if (!credentialFormat().equals(presentedFormat)) {
            return false;
        }
        String credentialType = mapperModel.getConfig().get(CREDENTIAL_TYPE);
        if (StringUtil.isBlank(credentialType)) {
            return true;
        }
        return credentialType
                .trim()
                .equals(context.getContextData().get(Oid4vpMapperUtils.CONTEXT_CREDENTIAL_TYPE_KEY));
    }

    /** The claims JSON of the verified presentation. */
    protected JsonNode credentialClaims(BrokeredIdentityContext context) {
        return Oid4vpMapperUtils.claimsNode(context);
    }

    /** The node claim paths of this mapper resolve against; mDoc mappers narrow it to a namespace. */
    protected JsonNode claimsRoot(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        return credentialClaims(context);
    }

    // Null when the claim is absent or the mapper is misconfigured.
    protected List<String> claimValues(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        if (!matchesCredential(mapperModel, context)) {
            return null;
        }
        String claimPath = mapperModel.getConfig().get(CLAIM);
        if (StringUtil.isBlank(claimPath)) {
            logger.warnf("No claim configured for mapper %s", mapperModel.getName());
            return null;
        }
        ClaimPath path = ClaimPath.parse(claimPath.trim());
        if (path == null) {
            logger.warnf("Invalid claim path '%s' in mapper %s", claimPath, mapperModel.getName());
            return null;
        }
        List<JsonNode> matches = path.select(claimsRoot(mapperModel, context));
        if (matches.isEmpty()) {
            return null;
        }
        Iterable<JsonNode> selected = matches.size() == 1 && matches.get(0).isArray() ? matches.get(0) : matches;
        // The values end up in the brokered context, whose serialization restores lists by their
        // concrete class, so they must stay plain ArrayLists.
        List<String> values = new ArrayList<>();
        for (JsonNode node : selected) {
            if (!node.isNull()) {
                values.add(value(node));
            }
        }
        return values;
    }

    protected String value(JsonNode node) {
        if (node.isValueNode()) {
            return node.asText();
        }
        try {
            return JsonSerialization.writeValueAsString(node);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize the claim value", e);
        }
    }
}
