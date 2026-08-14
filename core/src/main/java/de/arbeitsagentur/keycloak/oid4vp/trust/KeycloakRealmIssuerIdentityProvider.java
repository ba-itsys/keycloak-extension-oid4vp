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

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.JWKSServerUtils;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.utils.StringUtil;

/**
 * Trust material identity provider for credentials issued by this Keycloak.
 *
 * <p>Keycloak signs the credentials it issues with a realm key, so the trust material is that
 * realm's signature key material: the published JWKs bound to the realm's issuer identifier for
 * credentials that identify their key by {@code kid}, and the keys' certificates as directly
 * trusted issuer certificates for credentials that pin their leaf in {@code x5c}. Reading them in
 * process avoids Keycloak fetching its own metadata over HTTP, and a key rotation applies
 * immediately because passive keys stay published while credentials signed with them are still
 * valid.
 *
 * <p>A realm key whose certificate is issued by a CA is a plain X.509 trust domain instead: put
 * that CA into an {@link EtsiTrustListIdentityProvider} so presented chains are validated against
 * it.
 */
public class KeycloakRealmIssuerIdentityProvider
        implements Oid4vpTrustMaterialIdentityProvider<KeycloakRealmIssuerIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(KeycloakRealmIssuerIdentityProvider.class);

    /**
     * The signature key material of the issuing realm, as the trust material identity provider sees
     * it. Replaceable in tests with a typed double, the way the trust list provider is.
     */
    public interface RealmKeyMaterial {

        /** The realm issuer identifier the credentials carry as {@code iss}, or null when unknown. */
        String issuer();

        /** The realm's enabled signature keys as JWKs. */
        List<JWK> signatureKeys();

        /** The certificates of the realm's signature keys. */
        List<X509Certificate> certificates();
    }

    private final KeycloakRealmIssuerIdentityProviderConfig config;
    private final RealmKeyMaterial realmKeyMaterial;

    public KeycloakRealmIssuerIdentityProvider(
            KeycloakSession session, KeycloakRealmIssuerIdentityProviderConfig config) {
        this(config, new SessionRealmKeyMaterial(session, config));
    }

    KeycloakRealmIssuerIdentityProvider(
            KeycloakRealmIssuerIdentityProviderConfig config, RealmKeyMaterial realmKeyMaterial) {
        this.config = config;
        this.realmKeyMaterial = realmKeyMaterial;
    }

    @Override
    public KeycloakRealmIssuerIdentityProviderConfig getConfig() {
        return config;
    }

    @Override
    public List<String> servedCredentialTypes() {
        return config.getServedCredentialTypes();
    }

    @Override
    public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
        return trustedIssuerKeys().stream().map(TrustedIssuerKey::jwk);
    }

    @Override
    public List<TrustedIssuerKey> trustedIssuerKeys() {
        String issuer = realmKeyMaterial.issuer();
        if (StringUtil.isBlank(issuer)) {
            LOG.warnf(
                    "Trust material identity provider '%s': the issuer of the issuing realm cannot be determined, so "
                            + "its keys are not used. Configure the issuer explicitly.",
                    config.getAlias());
            return List.of();
        }
        List<TrustedIssuerKey> trustedIssuerKeys = new ArrayList<>();
        for (JWK jwk : realmKeyMaterial.signatureKeys()) {
            if (jwk != null && isSignatureKey(jwk)) {
                trustedIssuerKeys.add(new TrustedIssuerKey(issuer, jwk));
            }
        }
        return List.copyOf(trustedIssuerKeys);
    }

    @Override
    public List<X509Certificate> directIssuerCertificates() {
        return realmKeyMaterial.certificates();
    }

    @Override
    public void close() {}

    private static boolean isSignatureKey(JWK jwk) {
        return jwk.getPublicKeyUse() == null || KeyUse.SIG.getSpecName().equals(jwk.getPublicKeyUse());
    }

    /** Reads the key material of the issuing realm from the session, without leaving the server. */
    private record SessionRealmKeyMaterial(KeycloakSession session, KeycloakRealmIssuerIdentityProviderConfig config)
            implements RealmKeyMaterial {

        @Override
        public String issuer() {
            String configured = config.getIssuer();
            if (StringUtil.isNotBlank(configured)) {
                return configured.trim();
            }
            RealmModel realm = issuingRealm();
            URI frontendBaseUri = frontendBaseUri();
            return realm != null && frontendBaseUri != null ? Urls.realmIssuer(frontendBaseUri, realm.getName()) : null;
        }

        @Override
        public List<JWK> signatureKeys() {
            RealmModel realm = issuingRealm();
            if (realm == null) {
                return List.of();
            }
            JSONWebKeySet realmKeys = JWKSServerUtils.getRealmJwks(session, realm);
            return realmKeys.getKeys() != null ? List.of(realmKeys.getKeys()) : List.of();
        }

        @Override
        public List<X509Certificate> certificates() {
            RealmModel realm = issuingRealm();
            if (realm == null) {
                return List.of();
            }
            Set<X509Certificate> certificates = new LinkedHashSet<>();
            session.keys()
                    .getKeysStream(realm)
                    .filter(key -> key.getStatus() != null && key.getStatus().isEnabled())
                    .filter(key -> KeyUse.SIG.equals(key.getUse()))
                    .forEach(key -> collectCertificates(key, certificates));
            return List.copyOf(certificates);
        }

        private RealmModel issuingRealm() {
            String configuredRealm = config.getIssuerRealm();
            if (StringUtil.isBlank(configuredRealm)) {
                return session.getContext().getRealm();
            }
            RealmModel realm = session.realms().getRealmByName(configuredRealm.trim());
            if (realm == null) {
                LOG.warnf(
                        "Trust material identity provider '%s': the configured issuer realm '%s' does not exist",
                        config.getAlias(), configuredRealm);
            }
            return realm;
        }

        private URI frontendBaseUri() {
            try {
                return session.getContext().getUri(UrlType.FRONTEND).getBaseUri();
            } catch (RuntimeException e) {
                LOG.debugf("No frontend URI available for the realm issuer: %s", e.getMessage());
                return null;
            }
        }

        private static void collectCertificates(KeyWrapper key, Set<X509Certificate> certificates) {
            if (key.getCertificateChain() != null && !key.getCertificateChain().isEmpty()) {
                certificates.addAll(key.getCertificateChain());
            } else if (key.getCertificate() != null) {
                certificates.add(key.getCertificate());
            }
        }
    }
}
