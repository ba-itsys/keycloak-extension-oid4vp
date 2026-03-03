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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderFactory.class);

    private static final Map<String, String> RESOLVED_KEY_CACHE = new ConcurrentHashMap<>();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(Oid4vpIdentityProviderConfig.ENFORCE_HAIP)
                .label("Enforce HAIP Compliance")
                .helpText("Enable OpenID4VC High Assurance Interoperability Profile (HAIP) compliance. "
                        + "When enabled: client_id_scheme forced to x509_hash, response_mode set to direct_post.jwt "
                        + "(encrypted responses), and x509 certificate must be configured. "
                        + "Request objects are signed using the Keycloak realm signing key by default "
                        + "(ensure an ES256 key is active), or the x509 signing key if provided in the PEM.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
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
                                + "Leave empty to auto-generate from mappers.")
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
                .helpText("Scheme for client_id in redirect flows: x509_san_dns, x509_hash, or plain.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS)
                .options(List.of(
                        Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS,
                        Oid4vpConstants.CLIENT_ID_SCHEME_X509_HASH,
                        Oid4vpConstants.CLIENT_ID_SCHEME_PLAIN))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM)
                .label("X.509 Certificate (PEM)")
                .helpText("PEM-encoded X.509 certificate chain for x509 client ID schemes. "
                        + "Required when HAIP is enabled (x509_hash). "
                        + "May include a PRIVATE KEY block to override the realm signing key for request objects.")
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
                .name(Oid4vpIdentityProviderConfig.TRUST_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Trust List Cache TTL (seconds)")
                .helpText("Maximum time to cache the trust list (overrides JWT expiry if shorter). "
                        + "Leave empty to use the JWT's own expiration.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Status List Cache TTL (seconds)")
                .helpText("Maximum time to cache credential status lists (overrides JWT expiry if shorter). "
                        + "Leave empty to use the JWT's own expiration.")
                .type(ProviderConfigProperty.STRING_TYPE)
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

        return new Oid4vpIdentityProvider(session, config);
    }

    private static void validateHaipConfig(Oid4vpIdentityProviderConfig config) {
        if (config.isEnforceHaip() && StringUtil.isBlank(config.getX509CertificatePem())) {
            LOG.warnf(
                    "OID4VP IdP '%s': HAIP is enabled but no X.509 certificate is configured. "
                            + "The x509_hash client ID scheme requires a certificate.",
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
            if (!(leafCert.getPublicKey() instanceof ECPublicKey ecPub)) {
                LOG.warnf(
                        "Leaf certificate is not EC (got %s), cannot build signing key JWK",
                        leafCert.getPublicKey().getAlgorithm());
                return;
            }

            Curve curve = Curve.forECParameterSpec(ecPub.getParams());
            List<Base64> x5c = new ArrayList<>();
            for (X509Certificate cert : certChain) {
                x5c.add(Base64.encode(cert.getEncoded()));
            }

            ECKey ecKey = new ECKey.Builder(curve, ecPub)
                    .privateKey((ECPrivateKey) privateKey)
                    .x509CertChain(x5c)
                    .keyIDFromThumbprint()
                    .build();

            String jwkJson = ecKey.toJSONString();
            config.setX509SigningKeyJwk(jwkJson);
            RESOLVED_KEY_CACHE.put(pem, jwkJson);
            LOG.debugf(
                    "Resolved x509 signing key from inline PEM (chain size=%d, kid=%s)",
                    certChain.size(), ecKey.getKeyID());

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
