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
package de.arbeitsagentur.keycloak.oid4vp.trust;

import java.util.List;
import java.util.Map;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Factory of the OID4VP trust material identity provider. Instances expose trust anchors from an
 * ETSI trust list URL or a pasted PEM bundle and are referenced by OID4VP identity providers via
 * their {@code trustMaterialIdps} setting.
 */
public class EtsiTrustListIdentityProviderFactory
        extends AbstractIdentityProviderFactory<EtsiTrustListIdentityProvider> {

    public static final String PROVIDER_ID = "etsi-trust-list";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_URL)
            .label("Trust List URL")
            .helpText("URL of the ETSI TS 119 602 trust list JWT. The trust list is fetched, cached based on its "
                    + "freshness metadata, and refreshed automatically. Leave empty when trusted certificates "
                    + "are pasted below.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM)
            .label("Trust List Signing Certificate (PEM)")
            .helpText("PEM-encoded X.509 certificate used to verify the trust list JWT signature. "
                    + "If not configured, the trust list JWT signature is not verified and the fetched trust list "
                    + "is trusted as-is. This is acceptable for local testing only.")
            .type(ProviderConfigProperty.TEXT_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_LOTE_TYPE)
            .label("Trust List LoTE Type")
            .helpText("Expected List of Trusted Entities (LoTE) type of the trust list. "
                    + "Keep one trust domain per trust material provider instance. "
                    + "Leave empty only to accept all LoTE types from the configured trust list.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_CACHE_TTL_SECONDS)
            .label("Trust List Cache TTL (seconds)")
            .helpText("Maximum time to cache the trust list. "
                    + "Leave empty to use ETSI NextUpdate and HTTP cache headers.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_STALE_AGE_SECONDS)
            .label("Trust List Max Stale Age (seconds)")
            .helpText("Maximum age of a stale (expired) trust list cache entry that can be used as fallback "
                    + "when a trust list refresh fails (e.g., network timeout). "
                    + "Set to 0 to disable stale cache usage entirely.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(String.valueOf(EtsiTrustListIdentityProviderConfig.DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS))
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUSTED_CERTIFICATES)
            .label("Trusted Certificates (PEM)")
            .helpText("PEM-encoded X.509 certificate bundle of trusted issuers. CA certificates become trust "
                    + "anchors for credential certificate chains, end entity certificates are trusted directly. "
                    + "Used instead of or in addition to the trust list URL.")
            .type(ProviderConfigProperty.TEXT_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.SERVED_CREDENTIAL_TYPES)
            .label("Served Credential Types")
            .helpText("Comma separated credential types (SD-JWT VCT or mDoc doctype) this trust domain is "
                    + "responsible for. Credentials of these types are verified against this provider's material "
                    + "only, and their DCQL entries advertise its trusted authorities. Leave empty to serve every "
                    + "credential type of the OID4VP identity providers referencing this instance.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.ADVERTISE_TRUSTED_AUTHORITIES)
            .label("Advertise Trusted Authorities")
            .helpText("Whether the DCQL query tells wallets about this trust domain, as a 'trusted_authorities' "
                    + "entry of type 'etsi_tl' for the trust list URL and 'aki' for the key identifiers of the "
                    + "trusted certificates. Disable to keep an internal trust domain out of the authorization "
                    + "request; the verifier enforces it either way.")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .defaultValue("true")
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.REQUIRED_EXTENDED_KEY_USAGES)
            .label("Required Extended Key Usages")
            .helpText("Comma separated extended key usage OIDs. When set, credential signing certificates must "
                    + "contain at least one of them (e.g. 1.0.18013.5.1.2 for mDL document signers).")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "ETSI Trust List";
    }

    @Override
    public EtsiTrustListIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new EtsiTrustListIdentityProvider(session, new EtsiTrustListIdentityProviderConfig(model));
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String config) {
        throw new UnsupportedOperationException();
    }

    @Override
    public EtsiTrustListIdentityProviderConfig createConfig() {
        return new EtsiTrustListIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
