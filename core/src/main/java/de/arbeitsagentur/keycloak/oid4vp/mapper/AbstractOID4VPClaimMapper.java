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
import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialId;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeSpec;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.utils.StringUtil;

/**
 * Base for the OID4VP identity provider mappers, each of which reads one claim of the verified
 * credential presentation. Beyond mapping, the credential type and the optional claim sets a mapper
 * declares are what the generated DCQL query is built from.
 *
 * <p>Kept in sync with upstream Keycloak's {@code AbstractOID4VPClaimMapper}.
 */
public abstract class AbstractOID4VPClaimMapper extends AbstractIdentityProviderMapper {

    protected static final Logger logger = Logger.getLogger(AbstractOID4VPClaimMapper.class);

    public static final String CLAIM = "claim";
    public static final String CLAIM_ALTERNATIVES = "claim.alternatives";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CREDENTIAL_ID = "credential.id";
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

    protected static ProviderConfigProperty claimAlternativesProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CLAIM_ALTERNATIVES);
        property.setLabel("Alternative Claims");
        property.setHelpText("Comma-separated claim paths tried in order when the claim is not presented, in the "
                + "same notation as the claim. Use it when issuers name the same claim differently, i.e. "
                + "'birth_name' as an alternative to 'birth_family_name'. Each alternative is requested as a "
                + "claim of its own, and the generated claim sets ask for exactly one of them per option.");
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

    protected static ProviderConfigProperty credentialIdProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CREDENTIAL_ID);
        property.setLabel("Credential ID");
        property.setHelpText("Identifier of this credential in the generated DCQL query, referenced by the "
                + "identity provider's credential sets and used as the key the wallet answers under. "
                + "Only letters, digits, '_' and '-' are allowed. Leave empty to derive it from format and "
                + "first credential type, i.e. 'sdjwt_urn_eudi_pid_1' or 'mdoc_org_iso_18013_5_1_mDL'. Mappers "
                + "sharing a credential id are requested as one credential, so the same credential type can "
                + "be requested twice with different claims by giving the mappers different ids.");
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

    /** Returns the credential format this mapper covers, named as DCQL queries name it. */
    public abstract String credentialFormat();

    protected boolean matchesCredential(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        return presentedCredential(mapperModel, context) != null;
    }

    /**
     * Returns the presented credential named by this mapper's credential id, or the first presented
     * credential of the mapper's format when the mapper declares no credential type, and null when
     * neither is part of the presentation. No type comparison happens here, because the callback
     * has already checked that a presented credential is of a requested type.
     */
    protected PresentedCredential presentedCredential(
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        PresentedCredentials credentials = Oid4vpMapperUtils.presentedCredentials(context);
        if (credentials == null) {
            return null;
        }

        List<String> credentialTypes =
                CredentialTypeSpec.parseTypes(mapperModel.getConfig().get(CREDENTIAL_TYPE));
        if (credentialTypes.isEmpty()) {
            return credentials.firstOfFormat(credentialFormat());
        }

        PresentedCredential credential = credentials.get(credentialId(mapperModel, credentialTypes.get(0)));
        return credential != null && credentialFormat().equals(credential.format()) ? credential : null;
    }

    /**
     * Resolves the credential id this mapper reads under, mirroring how the DCQL query generation
     * derives it.
     */
    private String credentialId(IdentityProviderMapperModel mapperModel, String firstCredentialType) {
        return CredentialId.resolve(
                mapperModel.getConfig().get(CREDENTIAL_ID), credentialFormat(), firstCredentialType);
    }

    /** Returns the node the claim paths resolve against. mDoc mappers narrow it to a namespace. */
    protected JsonNode claimsRoot(IdentityProviderMapperModel mapperModel, PresentedCredential credential) {
        return credential.claimsNode();
    }

    /** Reports whether the claim source configuration is usable. mDoc mappers require a namespace. */
    protected boolean claimSourceConfigured(IdentityProviderMapperModel mapperModel) {
        return true;
    }

    /**
     * The two empty outcomes carry different obligations: a misconfigured mapper must leave the
     * brokered user untouched, while a well configured mapper whose claim the presentation does not
     * carry keeps the remove-on-absent update semantics.
     */
    protected record ClaimResolution(boolean misconfigured, List<String> values) {

        private static final ClaimResolution MISCONFIGURED = new ClaimResolution(true, List.of());
        private static final ClaimResolution ABSENT = new ClaimResolution(false, List.of());

        static ClaimResolution of(List<String> values) {
            return values.isEmpty() ? ABSENT : new ClaimResolution(false, values);
        }
    }

    /**
     * Resolves the configured claim and tells misconfiguration apart from an absent claim, trying
     * the claim path before the alternatives in the same order the generated claim set options
     * prefer them.
     */
    protected ClaimResolution resolveClaim(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        List<ClaimPath> paths = claimPaths(mapperModel);
        if (paths == null || !claimSourceConfigured(mapperModel)) {
            return ClaimResolution.MISCONFIGURED;
        }
        PresentedCredential credential = presentedCredential(mapperModel, context);
        if (credential == null) {
            return ClaimResolution.ABSENT;
        }
        JsonNode claimsRoot = claimsRoot(mapperModel, credential);
        for (ClaimPath path : paths) {
            List<String> values = ClaimSelection.values(path, claimsRoot);
            if (!values.isEmpty()) {
                return ClaimResolution.of(values);
            }
        }
        return ClaimResolution.ABSENT;
    }

    /**
     * Returns the claim path together with its alternatives, or null when any of them is missing or
     * malformed. One broken alternative makes the whole mapper misconfigured, which is also why the
     * DCQL generation skips it.
     */
    private List<ClaimPath> claimPaths(IdentityProviderMapperModel mapperModel) {
        String claimPath = mapperModel.getConfig().get(CLAIM);
        if (StringUtil.isBlank(claimPath)) {
            logger.warnf("No claim configured for mapper %s", mapperModel.getName());
            return null;
        }
        List<ClaimPath> paths = new ArrayList<>();
        ClaimPath path = ClaimPath.parse(claimPath.trim());
        if (path == null) {
            logger.warnf("Invalid claim path '%s' in mapper %s", claimPath, mapperModel.getName());
            return null;
        }
        paths.add(path);
        for (String alternative :
                ClaimSpec.parseAlternativePaths(mapperModel.getConfig().get(CLAIM_ALTERNATIVES))) {
            ClaimPath alternativePath = ClaimPath.parse(alternative);
            if (alternativePath == null) {
                logger.warnf("Invalid alternative claim path '%s' in mapper %s", alternative, mapperModel.getName());
                return null;
            }
            paths.add(alternativePath);
        }
        return paths;
    }

    protected String value(JsonNode node) {
        return ClaimSelection.value(node);
    }
}
