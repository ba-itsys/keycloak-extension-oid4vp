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
package de.arbeitsagentur.keycloak.oid4vp.issuance;

import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.OID4VCConstants;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Writes the subject and the reference credential binding of an OID4VP login into the credential this
 * Keycloak issues. The {@code oid4vp-subject-binding} authenticator records both on the entitlement
 * while the user signs in, and since the issuance runs in a session of its own, this mapper reads them
 * back from the entitlement of the credential scope it belongs to.
 */
public class Oid4vpBoundSubjectMapper extends OID4VCMapper {

    public static final String MAPPER_ID = "oid4vp-bound-subject-mapper";

    private static final Logger LOG = Logger.getLogger(Oid4vpBoundSubjectMapper.class);
    private static final String REFERENCE_BINDING_CLAIM = "referenceBindingClaim";
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(REFERENCE_BINDING_CLAIM)
            .label("Reference Binding Claim")
            .helpText("Claim the reference credential binding is written to. Set the same name in the "
                    + "'Reference Binding Claim' of the OID4VP identity provider that reads it.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(ReferenceCredentialBinding.DEFAULT_REFERENCE_BINDING_CLAIM)
            .add()
            .build();

    private final KeycloakSession session;

    public Oid4vpBoundSubjectMapper() {
        this(null);
    }

    private Oid4vpBoundSubjectMapper(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void setClaim(Map<String, Object> claims, UserSessionModel userSession) {
        List<String> claimPath = getMetadataAttributePath();
        if (claimPath.isEmpty()) {
            LOG.warn("OID4VP bound subject mapper: no claim name is set, so no subject is written");
            return;
        }
        UserVerifiableCredentialModel entitlement = entitlementOf(userSession);
        if (entitlement == null) {
            LOG.warnf(
                    "OID4VP bound subject mapper: user '%s' has no entitlement carrying an OID4VP subject, "
                            + "so no subject is written",
                    userSession.getUser().getId());
            return;
        }
        Map<String, List<String>> attributes = entitlement.getUserAttributes();
        String subject = first(attributes, ReferenceCredentialBinding.SUBJECT_ATTRIBUTE);
        if (subject == null) {
            LOG.warnf(
                    "OID4VP bound subject mapper: the entitlement of user '%s' carries no OID4VP subject, "
                            + "so no subject is written",
                    userSession.getUser().getId());
            return;
        }
        claims.put(claimPath.get(claimPath.size() - 1), subject);
        String referenceBinding = first(attributes, ReferenceCredentialBinding.REFERENCE_BINDING_ATTRIBUTE);
        if (referenceBinding != null) {
            claims.put(referenceBindingClaim(), referenceBinding);
        }
    }

    /**
     * Finds the entitlement of the credential scope this mapper belongs to. The scope is found through
     * the mapper itself, so nothing has to be configured twice.
     */
    private UserVerifiableCredentialModel entitlementOf(UserSessionModel userSession) {
        UserModel user = userSession.getUser();
        RealmModel realm = userSession.getRealm();
        if (session == null || user == null || realm == null || mapperModel == null) {
            return null;
        }
        return realm.getClientScopesStream()
                .filter(this::containsThisMapper)
                .map(scope -> session.users().getVerifiableCredentialByClientScope(user.getId(), scope.getId()))
                .filter(entitlement -> entitlement != null)
                .findFirst()
                .orElse(null);
    }

    private boolean containsThisMapper(ClientScopeModel scope) {
        return scope.getProtocolMappersStream()
                .anyMatch(mapper -> mapperModel.getId().equals(mapper.getId()));
    }

    private String referenceBindingClaim() {
        String claim = mapperModel.getConfig().get(REFERENCE_BINDING_CLAIM);
        return StringUtil.isBlank(claim) ? ReferenceCredentialBinding.DEFAULT_REFERENCE_BINDING_CLAIM : claim.trim();
    }

    private static String first(Map<String, List<String>> attributes, String name) {
        if (attributes == null) {
            return null;
        }
        List<String> values = attributes.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    @Override
    public void setClaim(VerifiableCredential verifiableCredential, UserSessionModel userSession) {
        // This extension issues SD-JWT. It does not use the W3C credential model of Keycloak.
    }

    // The subject comes from the entitlement the subject binding authenticator records, never from
    // a user attribute, so the reserved sub claim is the issuer's own value.
    @Override
    protected Set<String> getAllowedReservedClaims() {
        return Set.of(OID4VCConstants.CLAIM_NAME_SUB);
    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Bound Subject";
    }

    @Override
    public String getHelpText() {
        return "Writes the subject and the reference credential binding of an OID4VP login into the credential. "
                + "Add it to the credential scope the 'oid4vp-subject-binding' authenticator offers.";
    }

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        return new Oid4vpBoundSubjectMapper(session);
    }

    @Override
    public String getId() {
        return MAPPER_ID;
    }
}
