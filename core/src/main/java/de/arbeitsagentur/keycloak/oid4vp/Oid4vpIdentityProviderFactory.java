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

import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpRejectionResponse;
import de.arbeitsagentur.keycloak.oid4vp.util.BoundedLruMap;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpSigningKeyParser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import org.jboss.logging.Logger;
import org.keycloak.OID4VCConstants;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.utils.StringUtil;

public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProviderFactory.class);

    private static final int MAX_CACHE_ENTRIES = 256;

    // Keys the cache by a fingerprint of the PEM, because the raw PEM carries the private key and
    // must not stay in memory as a cache key.
    private static final Map<String, String> RESOLVED_KEY_CACHE = BoundedLruMap.withMaxEntries(MAX_CACHE_ENTRIES);
    private static final Set<String> WARNED_MISSING_TRUST_MATERIAL_IDPS =
            Collections.newSetFromMap(BoundedLruMap.withMaxEntries(MAX_CACHE_ENTRIES));

    private static String fingerprint(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64Url.encode(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint the verifier PEM", e);
        }
    }

    private static String loaHelpText(String flow) {
        return "Level of authentication a presentation over the " + flow + " flow reaches, as the integer of the "
                + "realm or client ACR-to-LoA mapping. The flow is offered only to requests of this level or below, "
                + "and a login whose presentation identified the user records the level in the session. Leave empty "
                + "for no level.";
    }

    private static String requestUriLifetimeHelpText(String flow) {
        return "How long a wallet can fetch the " + flow + " request object after the login page loads. "
                + "The login page then offers a new link. A wallet that fetched the request object "
                + "in time can send its presentation until the Keycloak authentication session expires.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(Oid4vpIdentityProviderConfig.RESPONSE_MODE)
                .label("Response Mode")
                .helpText("How the wallet posts its response to this verifier. direct_post.jwt encrypts the "
                        + "response and is what wallets following the high assurance profile expect.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(OID4VCConstants.RESPONSE_MODE_DIRECT_POST_JWT)
                .options(List.of(
                        OID4VCConstants.RESPONSE_MODE_DIRECT_POST, OID4VCConstants.RESPONSE_MODE_DIRECT_POST_JWT))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REJECTION_RESPONSE)
                .label("Rejected Presentation Response")
                .helpText("How the response URI answers a presentation this verifier rejects. 'redirect' answers "
                        + "with HTTP 200 and the redirect_uri that returns the user to the login page, or an empty "
                        + "object in a cross-device flow. 'error' answers with HTTP 400 and the error next to "
                        + "that redirect_uri, or the error alone in a cross-device flow. A wallet that stops on "
                        + "a non-2xx status then leaves the user in the wallet. Errors the wallet reports are always "
                        + "answered with HTTP 200.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .defaultValue(Oid4vpRejectionResponse.REDIRECT.configValue())
                .options(List.of(
                        Oid4vpRejectionResponse.REDIRECT.configValue(), Oid4vpRejectionResponse.ERROR.configValue()))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CREDENTIAL_SETS)
                .label("Credential Sets")
                .helpText("DCQL credential_sets as a JSON array in specification syntax (OID4VP 1.0 section 6.2), "
                        + "referencing the credential ids of the configured mappers. Each entry lists alternative "
                        + "credential combinations in order of preference, for example "
                        + "[{\"purpose\": \"Login\", \"options\": [[\"pid\", \"mdl\"], [\"pid\"]]}]. "
                        + "'required' defaults to true. Set it to false for an optional extra credential. "
                        + "Leave empty to require every configured credential.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES)
                .label("Principal Attributes")
                .helpText("The claims that identify the user, as a comma separated list of "
                        + "'credentialId:claimPath' entries in the order they are tried. Each entry names its "
                        + "credential, because credential formats keep the subject in different places. The path "
                        + "starts at the root of what the credential presents, so an mDoc path names the namespace "
                        + "before the element and escapes the dots of the namespace, for example "
                        + "'sdjwt_urn_eudi_pid_1:sub, mdoc_eu_europa_ec_eudi_pid_1:eu\\.europa\\.ec\\.eudi\\.pid\\.1"
                        + ".family_name'. The first named credential a wallet presents supplies the subject. Every "
                        + "required credential set option has to contain one of the named credentials, and each of "
                        + "them has to request its claim in every claim set option. Without entries and without "
                        + "transient users, the identity provider refuses logins and only serves the "
                        + "'oid4vp-presentation' authenticator and required action.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.ALLOW_MISSING_SUBJECT_CREDENTIAL)
                .label("Allow Missing Subject Credential")
                .helpText("Accepts a presentation that does not carry the subject credential, for credentials this "
                        + "Keycloak issues itself. Requires 'Principal Attributes', which names the subject "
                        + "credentials that may be missing. The verifier then generates a pseudonymous subject, and "
                        + "the first broker login establishes which user it belongs to. Configure a first broker "
                        + "login flow with 'idp-username-password-form' followed by 'oid4vp-subject-binding', which "
                        + "binds the login to that user so the credential issued afterwards identifies them.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REFERENCE_BINDING_CLAIM)
                .label("Reference Binding Claim")
                .helpText("Claim that carries the reference credential binding of a credential this Keycloak "
                        + "issues. Set the same name on the 'oid4vp-bound-subject-mapper' that writes it.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(ReferenceCredentialBinding.DEFAULT_REFERENCE_BINDING_CLAIM)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED)
                .label("Enable Same-Device Flow")
                .helpText("Offers a button that opens the wallet app on the device that shows the login page.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED)
                .label("Enable Cross-Device Flow")
                .helpText("Offers a QR code that the user scans with the wallet on another device, such as a phone.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_LOA)
                .label("Same-Device Max Level of Authentication")
                .helpText(loaHelpText("same-device"))
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CROSS_DEVICE_LOA)
                .label("Cross-Device Max Level of Authentication")
                .helpText(loaHelpText("cross-device"))
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.WALLET_SCHEME)
                .label("Wallet URL Scheme")
                .helpText("Where the button and the QR code send the authorization request: a custom URL scheme "
                        + "such as openid4vp:// or haip://, or the https authorization endpoint of a web wallet.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(Oid4vpConstants.DEFAULT_WALLET_SCHEME)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REQUEST_URI_METHOD_POST)
                .label("Request URI Method POST")
                .helpText("Adds request_uri_method=post, so a conforming wallet retrieves the request object with "
                        + "POST and sends its wallet_metadata and wallet_nonce (OID4VP 1.0 section 5.10). This "
                        + "enables request object encryption and wallet_nonce replay protection. Leave it off for "
                        + "wallets that retrieve the request object with GET only.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME)
                .label("Client ID Scheme")
                .helpText("How the verifier's client_id is formed. x509_hash uses the hash of the configured leaf "
                        + "certificate and x509_san_dns its DNS subject alternative name. Both require the X.509 "
                        + "certificate setting. plain uses the realm URL. Wallets following the high assurance "
                        + "profile expect x509_hash.")
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
                .helpText("PEM with the verifier certificate chain, leaf first, and the private key that signs the "
                        + "request object, as a PKCS#8 PRIVATE KEY or SEC1 EC PRIVATE KEY block. Required for the "
                        + "x509_san_dns and x509_hash client ID schemes. The key block may be left out when "
                        + "x509SigningKeyJwk supplies the key. Wallets following the high assurance profile expect "
                        + "a CA-issued chain. Accepts the value verbatim "
                        + "or Base64-encoded as a whole, for single-line sources such as environment variables.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.VERIFIER_INFO)
                .label("Verifier Info (JSON)")
                .helpText("JSON array of verifier attestations that the request object carries as verifier_info "
                        + "(OID4VP 1.0 section 5.1), such as an EUDI Wallet registration certificate. Accepts the "
                        + "value verbatim or Base64-encoded as a whole, for single-line sources such as environment "
                        + "variables.")
                .type(ProviderConfigProperty.TEXT_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.TRUST_MATERIAL_IDPS)
                .label("Trust Material Identity Providers")
                .helpText("Comma separated aliases of trust material identity providers, such as an ETSI trust list "
                        + "provider. Their certificates and keys verify the issuer signatures of credentials (SD-JWT "
                        + "x5c chains and mDoc COSE_Sign1) and of status lists. Without one, an SD-JWT issuer key "
                        + "comes only from the issuer's JWT VC Issuer Metadata and no mDoc can be verified.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REQUIRE_ISSUER_SAN_MATCH)
                .label("Require Issuer SAN Match")
                .helpText("Requires the iss value of an SD-JWT credential verified through its x5c chain to match a "
                        + "URI subject alternative name of the leaf certificate, or its https host to match a DNS "
                        + "subject alternative name. Applies to chains validated against a CA and to pinned leaf "
                        + "certificates.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.ISSUER_METADATA_MAX_CACHE_TTL_SECONDS)
                .label("Issuer Metadata Cache TTL (seconds)")
                .helpText("Maximum time to cache JWT VC Issuer Metadata and the issuer JWKS it points to. "
                        + "A shorter Cache-Control max-age from the issuer takes precedence. "
                        + "Set to 0 to disable caching.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(
                        String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_ISSUER_METADATA_MAX_CACHE_TTL_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS)
                .label("Status List Cache TTL (seconds)")
                .helpText("Maximum time to cache a credential status list. A status list is cached until its ttl "
                        + "or exp ends, and never longer than this value. Leave empty to follow ttl and exp alone.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.REQUEST_OBJECT_LIFESPAN_SECONDS)
                .label("Request Object Lifespan (seconds)")
                .helpText("How long the signed request object is valid after the wallet fetched it. "
                        + "The wallet processes it right away, so keep this short.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_REQUEST_OBJECT_LIFESPAN_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.SAME_DEVICE_REQUEST_URI_LIFETIME_SECONDS)
                .label("Same-Device Request URI Lifetime (seconds)")
                .helpText(requestUriLifetimeHelpText("same-device"))
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_REQUEST_URI_LIFETIME_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.CROSS_DEVICE_REQUEST_URI_LIFETIME_SECONDS)
                .label("Cross-Device Request URI Lifetime (seconds)")
                .helpText(requestUriLifetimeHelpText("cross-device"))
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_REQUEST_URI_LIFETIME_SECONDS))
                .add()
                .property()
                .name(Oid4vpIdentityProviderConfig.MAX_LIVE_REQUESTS_PER_LOGIN)
                .label("Maximum Live Wallet Requests per Login")
                .helpText("How many wallet requests of one login stay valid when the login page offers new links. "
                        + "Each page issues one request per enabled flow. Beyond this number the oldest requests "
                        + "end, and a wallet still answering one of them is rejected. At least 2.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Oid4vpIdentityProviderConfig.DEFAULT_MAX_LIVE_REQUESTS_PER_LOGIN))
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

    protected void validateTransientUserMode(Oid4vpIdentityProviderConfig config) {
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
        if (StringUtil.isBlank(config.getX509SigningKeyJwk())) {
            throw new IllegalStateException("The verifier certificate has no matching private key. Include the private"
                    + " key in the certificate PEM: a request object signed with the realm key cannot match the"
                    + " certificate-bound client_id, so every wallet rejects the authorization request.");
        }
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
        Matcher privateKeyBlock = pem == null ? null : Oid4vpIdentityProviderConfig.PRIVATE_KEY_BLOCK.matcher(pem);
        if (privateKeyBlock == null || !privateKeyBlock.find()) {
            return;
        }

        // PemUtils.decodeCertificates fails on mixed PEM content, so the key block is stripped first.
        List<String> certPemBlocks = extractPemBlocks(pem, "CERTIFICATE");
        String certOnlyPem = String.join("\n", certPemBlocks);
        config.setX509CertificatePem(certOnlyPem);

        String cacheKey = fingerprint(pem);
        String cached = RESOLVED_KEY_CACHE.get(cacheKey);
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

            PublicKey publicKey = certChain.get(0).getPublicKey();
            PrivateKey privateKey = privateKeyBlock.group(1).isEmpty()
                    ? PemUtils.decodePrivateKey(privateKeyBlock.group())
                    : Oid4vpSigningKeyParser.decodeSec1PrivateKey(
                            PemUtils.pemToDer(privateKeyBlock.group()), publicKey);

            String jwkJson = Oid4vpSigningKeyParser.serialize(publicKey, privateKey, certChain);
            config.setX509SigningKeyJwk(jwkJson);
            RESOLVED_KEY_CACHE.put(cacheKey, jwkJson);
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
