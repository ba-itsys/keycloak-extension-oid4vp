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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpSigningKeyParser;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.common.Profile;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

/**
 * Keycloak SPI factory for the OID4VP Identity Provider.
 *
 * <p>Registered via {@code META-INF/services} and discovered by Keycloak at startup.
 * Defines all configuration properties shown in the Admin Console, resolves X.509 signing keys
 * from inline PEM certificates, and validates the verifier certificate on provider creation.
 */
public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderFactory.class);

    private static final Map<String, String> RESOLVED_KEY_CACHE = new ConcurrentHashMap<>();
    private static final Set<String> WARNED_MISSING_TRUST_MATERIAL_IDPS = ConcurrentHashMap.newKeySet();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(Oid4vpIdentityProviderConfig.RESPONSE_MODE)
                .label("Response Mode")
                .helpText("Response mode for wallet callbacks. direct_post.jwt encrypts the wallet response "
                        + "and is what wallets following the high assurance profile expect.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpConstants.RESPONSE_MODE_DIRECT_POST_JWT)
                .options(List.of(
                        Oid4vpConstants.RESPONSE_MODE_DIRECT_POST, Oid4vpConstants.RESPONSE_MODE_DIRECT_POST_JWT))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SETS)
                .label("Credential Sets")
                .helpText("DCQL credential_sets constraints in specification syntax, referencing the credential ids "
                        + "of the configured mappers. Each entry lists alternative credential combinations in "
                        + "preference order, i.e. "
                        + "[{\"purpose\": \"Login\", \"options\": [[\"pid\", \"mdl\"], [\"pid\"]]}]. "
                        + "'required' defaults to true; set it to false for an optional extra credential. "
                        + "Leave empty to require every configured credential.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES)
                .label("Principal Attributes")
                .helpText("The claims that identify the user, as a comma separated list of "
                        + "'credentialId:claimPath' entries in the order they are tried. The claim belongs to the "
                        + "credential because credentials do not agree on where the subject sits: the path starts at "
                        + "the root of what the credential presents, so an mDoc names its namespace before the "
                        + "element, with the dots of the namespace escaped, i.e. "
                        + "'sdjwt_urn_eudi_pid_1:sub, mdoc_eu_europa_ec_eudi_pid_1:eu\\.europa\\.ec\\.eudi\\.pid\\.1"
                        + ".family_name'. The first named credential a wallet presents supplies the subject, every "
                        + "required credential set option has to contain one of them, and each has to request its "
                        + "claim in every claim set option. "
                        + "requested. Required unless OID4VP transient users are enabled.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.ALLOW_MISSING_SUBJECT_CREDENTIAL)
                .label("Allow Missing Subject Credential")
                .helpText("Accepts a presentation that does not carry the subject credential, for credentials this "
                        + "Keycloak issues itself. Requires 'Principal Attributes', which says which credentials "
                        + "may be missing. The verifier then generates a pseudonymous subject, and the first broker "
                        + "login establishes which user it belongs to. Configure a first broker login flow with "
                        + "'idp-username-password-form' followed by 'oid4vp-subject-binding', which binds the login "
                        + "to that user so the credential issued afterwards identifies them.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED)
                .label("Enable Same-Device Flow")
                .helpText("Enable same-device flow (redirect to wallet app on same device).")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED)
                .label("Enable Cross-Device Flow")
                .helpText("Enable cross-device flow (QR code for scanning with phone).")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.WALLET_SCHEME)
                .label("Wallet URL Scheme")
                .helpText("Custom URL scheme for wallet apps (e.g., openid4vp://, haip://).")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(Oid4vpConstants.DEFAULT_WALLET_SCHEME)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME)
                .label("Client ID Scheme")
                .helpText("Scheme for client_id in redirect flows. x509_hash identifies the verifier by the hash "
                        + "of its certificate and is what wallets following the high assurance profile expect.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpClientIdScheme.X509_HASH.configValue())
                .options(List.of(
                        Oid4vpClientIdScheme.X509_SAN_DNS.configValue(),
                        Oid4vpClientIdScheme.X509_HASH.configValue(),
                        Oid4vpClientIdScheme.PLAIN.configValue()))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM)
                .label("X.509 Certificate (PEM)")
                .helpText(
                        "PEM-encoded X.509 certificate chain for x509_san_dns or x509_hash client ID schemes. "
                                + "Required whenever the effective client ID scheme is certificate-bound. "
                                + "May include a PRIVATE KEY block to override the realm signing key for request objects. "
                                + "Wallets following the high assurance profile expect a CA-issued chain, not a self-signed leaf.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.VERIFIER_INFO)
                .label("Verifier Info (JSON)")
                .helpText("JSON array of verifier attestations for EUDI Wallet registration certificates.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_MATERIAL_IDPS)
                .label("Trust Material Identity Providers")
                .helpText("Comma separated aliases of trust material identity providers (e.g. an ETSI Trust List "
                        + "provider) used to verify issuer signatures on credentials (SD-JWT x5c chains and mDoc "
                        + "COSE_Sign1) and status lists. If empty, credential signature verification has no trust "
                        + "anchors and relies on issuer metadata resolution where allowed.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.ISSUER_METADATA_MAX_CACHE_TTL_SECONDS)
                .label("Issuer Metadata Cache TTL (seconds)")
                .helpText("Maximum time to cache JWT VC Issuer Metadata and resolved issuer JWKS. "
                        + "If the remote Cache-Control max-age is shorter, that shorter lifetime is used. "
                        + "Set to 0 to disable caching.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(
                        String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_ISSUER_METADATA_MAX_CACHE_TTL_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Status List Cache TTL (seconds)")
                .helpText(
                        "Maximum time to cache credential status lists (overrides status-list ttl/expiry if shorter). "
                                + "Leave empty to use the status list's own ttl, capped by exp if present.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REQUEST_OBJECT_LIFESPAN_SECONDS)
                .label("Request Object Lifespan (seconds)")
                .helpText("How long the signed request object JWT is valid. "
                        + "The wallet fetches and processes it immediately, so this should be short.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_REQUEST_OBJECT_LIFESPAN_SECONDS))
                .add()
                .build();
    }

    @Override
    public String getId() {
        return Oid4vpConstants.PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "OID4VP (Wallet Login)";
    }

    @Override
    public Oid4vpIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig(model);
        validateTransientUserMode(config);

        resolveX509SigningKey(config);
        validateVerifierCertificate(config);
        warnIfTrustMaterialIdpsAreMissing(config);

        return new Oid4vpIdentityProvider(session, config);
    }

    private void validateTransientUserMode(Oid4vpIdentityProviderConfig config) {
        if (config.isTransientUsersEnabled() && !isTransientUsersFeatureEnabled()) {
            throw new IllegalStateException(
                    "OID4VP transient users require the Keycloak feature 'transient-users' to be enabled.");
        }
    }

    private boolean isTransientUsersFeatureEnabled() {
        return Profile.getInstance() != null && Profile.isFeatureEnabled(Profile.Feature.TRANSIENT_USERS);
    }

    static void validateVerifierCertificate(Oid4vpIdentityProviderConfig config) {
        if (!config.getResolvedClientIdScheme().isCertificateBound()) {
            return;
        }

        config.getResolvedClientIdScheme().validateCertificateBinding(config.getX509CertificatePem());
    }

    private static void warnIfTrustMaterialIdpsAreMissing(Oid4vpIdentityProviderConfig config) {
        if (StringUtil.isNotBlank(config.getTrustMaterialIdps())) {
            return;
        }
        if (WARNED_MISSING_TRUST_MATERIAL_IDPS.add(config.getAlias())) {
            LOG.warnf(
                    "OID4VP IdP '%s': trustMaterialIdps is empty. Credential signature verification has no trust "
                            + "anchors; configure a trust material identity provider (e.g. etsi-trust-list).",
                    config.getAlias());
        }
    }

    @Override
    public Oid4vpIdentityProviderConfig createConfig() {
        return new Oid4vpIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public static void resolveX509SigningKey(Oid4vpIdentityProviderConfig config) {
        String existingJwk = config.getX509SigningKeyJwk();
        if (StringUtil.isNotBlank(existingJwk)) {
            return;
        }

        String pem = config.getX509CertificatePem();
        if (pem == null || !pem.contains("-----BEGIN PRIVATE KEY-----")) {
            return;
        }

        // Strip non-certificate blocks (e.g. PRIVATE KEY) before parsing,
        // because PemUtils.decodeCertificates fails on mixed PEM content.
        List<String> certPemBlocks = extractPemBlocks(pem, "CERTIFICATE");
        String certOnlyPem = String.join("\n", certPemBlocks);
        config.setX509CertificatePem(certOnlyPem);

        String cached = RESOLVED_KEY_CACHE.get(pem);
        if (cached != null) {
            config.setX509SigningKeyJwk(cached);
            return;
        }

        try {
            X509Certificate[] certs = PemUtils.decodeCertificates(certOnlyPem);
            List<X509Certificate> certChain = Arrays.asList(certs);
            if (certChain.isEmpty()) {
                LOG.warn("No certificates found in x509CertificatePem");
                return;
            }

            List<String> keyBlocks = extractPemBlocks(pem, "PRIVATE KEY");
            if (keyBlocks.isEmpty()) {
                LOG.warn("No PRIVATE KEY block found in x509CertificatePem");
                return;
            }
            PrivateKey privateKey = PemUtils.decodePrivateKey(keyBlocks.get(0));

            X509Certificate leafCert = certChain.get(0);
            PublicKey publicKey = leafCert.getPublicKey();

            String jwkJson = Oid4vpSigningKeyParser.serialize(publicKey, privateKey, certChain);
            config.setX509SigningKeyJwk(jwkJson);
            RESOLVED_KEY_CACHE.put(pem, jwkJson);
            LOG.debugf(
                    "Resolved x509 signing key from inline PEM (chain size=%d, kid=%s)",
                    certChain.size(), Oid4vpSigningKeyParser.extractKid(jwkJson));

        } catch (Exception e) {
            throw new IllegalStateException(
                    "x509CertificatePem contains a PRIVATE KEY block but the signing key could not be resolved. "
                            + "Fix or remove the private key from the PEM configuration.",
                    e);
        }
    }

    private static List<String> extractPemBlocks(String pem, String type) {
        List<String> blocks = new ArrayList<>();
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int idx = 0;
        while (true) {
            int start = pem.indexOf(begin, idx);
            if (start < 0) break;
            int stop = pem.indexOf(end, start);
            if (stop < 0) break;
            blocks.add(pem.substring(start, stop + end.length()));
            idx = stop + end.length();
        }
        return blocks;
    }
}
