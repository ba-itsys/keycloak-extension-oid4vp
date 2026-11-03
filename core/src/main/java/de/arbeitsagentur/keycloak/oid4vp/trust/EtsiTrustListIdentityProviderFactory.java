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
            .helpText("PEM-encoded X.509 certificates of the list signer, several for key rotation. Only their "
                    + "keys verify the trust list JWT signature, so a CA certificate does not vouch for what it issues. "
                    + "Without it, the signature is not verified and the fetched trust list is trusted as is. "
                    + "Use that for local testing only. "
                    + "Accepts the value verbatim or Base64-encoded as a whole, for single-line sources such as "
                    + "environment variables.")
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
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_SERVICE_STATUSES)
            .label("Trust List Service Statuses")
            .helpText("Comma separated service statuses that count as current. A service without a status is "
                    + "always trusted, because most LoTE types have none. A service with any other status adds "
                    + "no certificates. A Pub-EAA providers list needs "
                    + "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_CACHE_TTL_SECONDS)
            .label("Trust List Cache TTL (seconds)")
            .helpText("Maximum time to cache the trust list. A list is cached until its ETSI NextUpdate and never "
                    + "longer than this value, so it decides how soon a withdrawn CA stops being trusted. HTTP cache "
                    + "headers do not apply. A list without NextUpdate is closed and trusts nothing. "
                    + "Set to 0 to fetch on every use.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(String.valueOf(EtsiTrustListIdentityProviderConfig.DEFAULT_TRUST_LIST_MAX_CACHE_TTL_SECONDS))
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUST_LIST_MAX_STALE_AGE_SECONDS)
            .label("Trust List Max Stale Age (seconds)")
            .helpText("How long after its last download a list past NextUpdate stays in use when a refresh "
                    + "fails. Set to 0 to stop using a list past NextUpdate.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(String.valueOf(EtsiTrustListIdentityProviderConfig.DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS))
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.TRUSTED_CERTIFICATES)
            .label("Trusted Certificates (PEM)")
            .helpText("PEM-encoded X.509 certificate bundle of trusted issuers. CA certificates become trust "
                    + "anchors for credential certificate chains. End entity certificates are trusted directly. "
                    + "Used instead of or in addition to the trust list URL. "
                    + "Accepts the value verbatim or Base64-encoded as a whole, for single-line sources such as "
                    + "environment variables.")
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
            .label("Advertised Trusted Authority Type")
            .helpText("The 'trusted_authorities' entry the DCQL query tells wallets about: 'etsi_tl' advertises "
                    + "the trust list URL, 'aki' the key identifiers of the trusted certificates. Empty "
                    + "advertises nothing. At most one entry per trust domain, because both types describe the "
                    + "same anchors. The verifier enforces the trust either way.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.CRL_ENDPOINT)
            .label("CRL Endpoint")
            .helpText("Fixed URL of the CRL for issuer signing certificates. It replaces the CRL distribution "
                    + "points of the certificate that signed the credential, and it must serve a CRL of that "
                    + "certificate's issuer. Intermediate certificates keep their own distribution points. Leave "
                    + "empty to use the distribution points alone.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.CRL_MAX_CACHE_TTL_SECONDS)
            .label("CRL Cache TTL (seconds)")
            .helpText("Maximum time to cache a CRL. A CRL is cached until its nextUpdate and never longer than "
                    + "this value. This value decides how soon a revocation takes effect. A background task "
                    + "downloads CRLs. A login uses the cached CRL and waits up to 3 seconds only when none is known yet. A failed download logs a warning, the last known CRL "
                    + "stays in use, and the failure is cached for this time. With Require CRL and no known CRL, each "
                    + "login tries the download again.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(String.valueOf(CrlPolicy.DEFAULT_MAX_CACHE_TTL_SECONDS))
            .add()
            .property()
            .name(EtsiTrustListIdentityProviderConfig.CRL_REQUIRED)
            .label("Require CRL")
            .helpText("Rejects a credential when no CRL is known for a certificate that names one or that the CRL "
                    + "endpoint covers, or when the check cannot run for a chain. An unreachable "
                    + "CA then stops the logins of its issuers until a CRL is known. When off, Keycloak accepts "
                    + "such a credential unchecked. ISO/IEC 18013-5 requires revocation information for mDL.")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .defaultValue("false")
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
