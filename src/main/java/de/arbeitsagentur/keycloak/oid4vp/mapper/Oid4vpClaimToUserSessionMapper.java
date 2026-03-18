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

import static de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperConfigProperties.*;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperConfigProperties;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.utils.StringUtil;

/**
 * Maps claims from verified OID4VP credentials to Keycloak user session notes.
 *
 * <p>Session notes are transient key-value pairs attached to the user session. They can be
 * included in tokens using a "User Session Note" protocol mapper. This is useful for passing
 * credential claims (e.g. issuer, credential type) through to relying parties without persisting
 * them as user attributes. Also drives DCQL query generation like the attribute mapper.
 */
public class Oid4vpClaimToUserSessionMapper extends AbstractIdentityProviderMapper {

    private static final Logger LOG = Logger.getLogger(Oid4vpClaimToUserSessionMapper.class);

    public static final String PROVIDER_ID = "oid4vp-user-session-mapper";

    public static final String SESSION_NOTE = "session.note";
    static final String CONTEXT_SESSION_NOTES_KEY = "MAPPER_SESSION_NOTES";

    private static final String[] COMPATIBLE_PROVIDERS = new String[] {Oid4vpConstants.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        Oid4vpMapperConfigProperties.addCommonProperties(CONFIG_PROPERTIES);

        ProviderConfigProperty sessionNoteProperty = new ProviderConfigProperty();
        sessionNoteProperty.setName(SESSION_NOTE);
        sessionNoteProperty.setLabel("Session Note Key");
        sessionNoteProperty.setHelpText(
                "Key name for storing the claim value in the user session. Use a 'User Session Note' protocol mapper to include in tokens.");
        sessionNoteProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(sessionNoteProperty);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Claim to User Session";
    }

    @Override
    public String getHelpText() {
        return "Map a claim from the verifiable credential to a user session note.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public void preprocessFederatedIdentity(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        mapSessionNote(mapperModel, context);
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        mapSessionNote(mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        mapSessionNote(mapperModel, context);
    }

    private void mapSessionNote(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        if (!Oid4vpMapperUtils.matchesCredential(mapperModel, context)) {
            return;
        }

        String claimPath = mapperModel.getConfig().get(CLAIM_PATH);
        String sessionNote = mapperModel.getConfig().get(SESSION_NOTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (StringUtil.isBlank(claimPath) || StringUtil.isBlank(sessionNote)) {
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (!isOptional) {
                LOG.warnf("Required claim '%s' not found in credential", claimPath);
            }
            return;
        }

        String stringValue = Oid4vpMapperUtils.toStringValue(claimValue);
        if (stringValue == null) return;
        ensureContextSessionNotes(context).put(sessionNote, stringValue);
        context.setSessionNote(sessionNote, stringValue);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> ensureContextSessionNotes(BrokeredIdentityContext context) {
        Object existing = context.getContextData().get(CONTEXT_SESSION_NOTES_KEY);
        if (existing instanceof Map<?, ?> sessionNotes) {
            return (Map<String, String>) sessionNotes;
        }

        Map<String, String> sessionNotes = new HashMap<>();
        context.getContextData().put(CONTEXT_SESSION_NOTES_KEY, sessionNotes);
        return sessionNotes;
    }
}
