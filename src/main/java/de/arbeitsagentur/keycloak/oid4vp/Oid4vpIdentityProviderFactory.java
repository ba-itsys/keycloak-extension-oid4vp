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
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpTrustedAuthoritiesMode;
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
 * from inline PEM certificates, and validates HAIP configuration on provider creation.
 */
public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderFactory.class);

    private static final Map<String, String> RESOLVED_KEY_CACHE = new ConcurrentHashMap<>();
    private static final Set<String> WARNED_UNCHECKED_TRUST_LISTS = ConcurrentHashMap.newKeySet();
    private static final Set<String> WARNED_MISSING_CERTIFICATE_BINDINGS = ConcurrentHashMap.newKeySet();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(Oid4vpIdentityProviderConfig.ENFORCE_HAIP)
                .label("Enforce HAIP Compliance")
                .helpText("Enable OpenID4VC High Assurance Interoperability Profile (HAIP) compliance. "
                        + "When enabled, the effective response_mode is forced to direct_post.jwt and the "
                        + "effective client_id_scheme is forced to x509_hash. "
                        + "Request objects are signed using the Keycloak realm signing key by default "
                        + "(ensure an ES256 key is active), or the x509 signing key if provided in the PEM.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.RESPONSE_MODE)
                .label("Response Mode")
                .helpText("Response mode for wallet callbacks: direct_post or direct_post.jwt. "
                        + "HAIP overrides this to direct_post.jwt.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpConstants.RESPONSE_MODE_DIRECT_POST)
                .options(List.of(
                        Oid4vpConstants.RESPONSE_MODE_DIRECT_POST, Oid4vpConstants.RESPONSE_MODE_DIRECT_POST_JWT))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE)
                .label("Credential Set Mode")
                .helpText(
                        "When multiple credential types are configured via mappers: 'optional' requires any one credential, 'all' requires all.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_OPTIONAL)
                .options(List.of(
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_OPTIONAL,
                        Oid4vpIdentityProviderConfig.CREDENTIAL_SET_MODE_ALL))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SET_PURPOSE)
                .label("Credential Set Purpose")
                .helpText("Optional purpose description for the credential request (shown to user in wallet).")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.DCQL_QUERY)
                .label("DCQL Query (JSON)")
                .helpText(
                        "Explicit DCQL query JSON. Priority: (1) this if set, (2) auto-generated from mappers, (3) default. "
                                + "Leave empty to auto-generate from mappers. Missing credential metadata is normalized automatically.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM)
                .label("User Identifier Claim (SD-JWT)")
                .helpText("Claim name used to identify the user from SD-JWT credentials (e.g., 'sub').")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("sub")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC)
                .label("User Identifier Claim (mDoc)")
                .helpText(
                        "Claim name used to identify the user from mDoc credentials. Falls back to SD-JWT claim if not set.")
                .type(ProviderConfigProperty.STRING_TYPE)
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
                .helpText("Scheme for client_id in redirect flows: x509_san_dns, x509_hash, or plain. "
                        + "HAIP overrides this to x509_hash.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpClientIdScheme.X509_SAN_DNS.configValue())
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
                                + "When HAIP is enabled for x509_hash, configure a CA-issued verifier chain, not a self-signed leaf.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.VERIFIER_INFO)
                .label("Verifier Info (JSON)")
                .helpText("JSON array of verifier attestations for EUDI Wallet registration certificates.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_LIST_URL)
                .label("Trust List URL")
                .helpText("URL of the ETSI TS 119 612 trust list JWT. "
                        + "Used to verify issuer signatures on credentials (SD-JWT x5c chains and mDoc COSE_Sign1). "
                        + "If empty, credential signature verification is skipped.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUSTED_AUTHORITIES_MODE)
                .label("Trusted Authorities Mode")
                .helpText("Adds one 'trusted_authorities' constraint type to each credential in the DCQL query. "
                        + "'none' disables the feature, 'etsi_tl' advertises the trust list URL, and 'aki' advertises certificate key identifiers extracted from the trust list. "
                        + "This is opt-in and independent of HAIP.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpTrustedAuthoritiesMode.NONE.configValue())
                .options(List.of(
                        Oid4vpTrustedAuthoritiesMode.NONE.configValue(),
                        Oid4vpTrustedAuthoritiesMode.ETSI_TL.configValue(),
                        Oid4vpTrustedAuthoritiesMode.AKI.configValue()))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_LIST_SIGNING_CERT_PEM)
                .label("Trust List Signing Certificate (PEM)")
                .helpText("PEM-encoded X.509 certificate used to verify the trust list JWT signature. "
                        + "If not configured, the trust list JWT signature is not verified and the fetched trust list is trusted as-is. "
                        + "This is acceptable for local testing only.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Trust List Cache TTL (seconds)")
                .helpText("Maximum time to cache the trust list (overrides JWT expiry if shorter). "
                        + "Leave empty to use the JWT's own expiration.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_LIST_MAX_STALE_AGE_SECONDS)
                .label("Trust List Max Stale Age (seconds)")
                .helpText("Maximum age of a stale (expired) trust list cache entry that can be used as fallback "
                        + "when a trust list refresh fails (e.g., network timeout). "
                        + "Set to 0 to disable stale cache usage entirely.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_TRUST_LIST_MAX_STALE_AGE_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.USE_ID_TOKEN_SUBJECT)
                .label("Use ID Token Subject (SIOPv2)")
                .helpText("When enabled, requests a Self-Issued ID Token alongside the VP Token. "
                        + "The user's subject is determined from the ID Token's sub claim (JWK Thumbprint) "
                        + "instead of a credential claim. The VP Token is still required for credential attributes.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Status List Cache TTL (seconds)")
                .helpText("Maximum time to cache credential status lists (overrides JWT expiry if shorter). "
                        + "Leave empty to use the JWT's own expiration.")
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

        resolveX509SigningKey(config);
        validateHaipConfig(config);
        warnIfTrustListSignatureIsUnchecked(config);

        return new Oid4vpIdentityProvider(session, config);
    }

    private static void validateHaipConfig(Oid4vpIdentityProviderConfig config) {
        if (!config.getResolvedClientIdScheme().isCertificateBound()) {
            return;
        }

        if (!config.isEnforceHaip() && StringUtil.isBlank(config.getX509CertificatePem())) {
            String warningKey =
                    config.getAlias() + "|" + config.getResolvedClientIdScheme().configValue();
            if (WARNED_MISSING_CERTIFICATE_BINDINGS.add(warningKey)) {
                LOG.warnf(
                        "OID4VP IdP '%s': The effective client_id_scheme requires an X.509 certificate, but none is configured. "
                                + "Certificate-bound client_id schemes require a certificate.",
                        config.getAlias());
            }
            return;
        }

        config.getResolvedClientIdScheme()
                .validateCertificateBinding(config.getX509CertificatePem(), config.isEnforceHaip());
    }

    private static void warnIfTrustListSignatureIsUnchecked(Oid4vpIdentityProviderConfig config) {
        if (StringUtil.isBlank(config.getTrustListUrl())
                || StringUtil.isNotBlank(config.getTrustListSigningCertPem())) {
            return;
        }
        String warningKey = config.getAlias() + "|" + config.getTrustListUrl();
        if (WARNED_UNCHECKED_TRUST_LISTS.add(warningKey)) {
            LOG.warnf(
                    "OID4VP IdP '%s': trustListUrl is configured but trustListSigningCertPem is empty. "
                            + "The trust list JWT signature will not be verified and fetched trust anchors will be trusted as-is.",
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
