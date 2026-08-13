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

import de.arbeitsagentur.keycloak.oid4vp.verification.TrustListProvider;
import de.arbeitsagentur.keycloak.oid4vp.verification.X5cChainValidator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Trust material identity provider backed by an ETSI TS 119 602 trust list URL, a pasted PEM
 * certificate bundle, or both.
 *
 * <p>CA certificates become X.509 trust anchors for credential issuer chain validation, end entity
 * certificates are trusted directly (pinned leaf or chainless credentials) through
 * {@link #directIssuerCertificates()}. The provider does not authenticate users; OID4VP identity
 * providers reference it by alias through their {@code trustMaterialIdps} setting.
 */
public class EtsiTrustListIdentityProvider
        implements Oid4vpTrustMaterialIdentityProvider<EtsiTrustListIdentityProviderConfig> {

    private final EtsiTrustListIdentityProviderConfig config;
    private final TrustListProvider urlTrustList;
    private final TrustListProvider staticTrustList;

    public EtsiTrustListIdentityProvider(KeycloakSession session, EtsiTrustListIdentityProviderConfig config) {
        this(
                config,
                StringUtil.isNotBlank(config.getTrustListUrl())
                        ? new TrustListProvider(
                                session,
                                config.getTrustListUrl(),
                                config.getTrustListMaxCacheTtl(),
                                config.getTrustListMaxStaleAge(),
                                config.parseTrustListSigningCerts())
                        : null,
                staticTrustListOf(config));
    }

    EtsiTrustListIdentityProvider(
            EtsiTrustListIdentityProviderConfig config,
            TrustListProvider urlTrustList,
            TrustListProvider staticTrustList) {
        this.config = config;
        this.urlTrustList = urlTrustList;
        this.staticTrustList = staticTrustList;
    }

    private static TrustListProvider staticTrustListOf(EtsiTrustListIdentityProviderConfig config) {
        List<X509Certificate> pastedCertificates = config.parseTrustedCertificates();
        return pastedCertificates.isEmpty() ? null : new TrustListProvider(pastedCertificates);
    }

    @Override
    public EtsiTrustListIdentityProviderConfig getConfig() {
        return config;
    }

    @Override
    public Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
        Set<X509Certificate> anchors = new LinkedHashSet<>();
        for (X509Certificate certificate : issuanceCertificates()) {
            if (X5cChainValidator.isCaCertificate(certificate)) {
                anchors.add(certificate);
            }
        }
        if (anchors.isEmpty()) {
            return Stream.empty();
        }
        return Stream.of(new X509TrustMaterial(anchors, config.getRequiredExtendedKeyUsages()));
    }

    // End entity certificates are served through directIssuerCertificates; exposing them here as
    // JWKs would duplicate that trust for the extension's consumers.
    @Override
    public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
        return Stream.empty();
    }

    @Override
    public List<X509Certificate> directIssuerCertificates() {
        return issuanceCertificates();
    }

    @Override
    public List<X509Certificate> revocationCertificates() {
        List<X509Certificate> certificates = new ArrayList<>();
        if (urlTrustList != null) {
            certificates.addAll(urlTrustList.getRevocationCertificates());
            enforceExpectedLoTEType();
        }
        if (staticTrustList != null) {
            certificates.addAll(staticTrustList.getRevocationCertificates());
        }
        return List.copyOf(certificates);
    }

    @Override
    public List<String> trustedAuthorityKeyIdentifiers() {
        Set<String> identifiers = new LinkedHashSet<>();
        if (urlTrustList != null) {
            identifiers.addAll(urlTrustList.getTrustedAuthorityKeyIdentifiers());
            enforceExpectedLoTEType();
        }
        if (staticTrustList != null) {
            identifiers.addAll(staticTrustList.getTrustedAuthorityKeyIdentifiers());
        }
        return List.copyOf(identifiers);
    }

    @Override
    public Optional<String> trustListUrl() {
        return Optional.ofNullable(config.getTrustListUrl()).filter(StringUtil::isNotBlank);
    }

    @Override
    public void close() {}

    private List<X509Certificate> issuanceCertificates() {
        List<X509Certificate> certificates = new ArrayList<>();
        if (urlTrustList != null) {
            certificates.addAll(urlTrustList.getIssuanceCertificates());
            enforceExpectedLoTEType();
        }
        if (staticTrustList != null) {
            certificates.addAll(staticTrustList.getIssuanceCertificates());
        }
        return List.copyOf(certificates);
    }

    private void enforceExpectedLoTEType() {
        String expected = config.getTrustListLoTEType();
        if (StringUtil.isBlank(expected)) {
            return;
        }
        String actual = urlTrustList.getCurrentLoTEType();
        if (StringUtil.isNotBlank(actual) && !expected.equals(actual)) {
            throw new IdentityBrokerException(
                    "Trust list LoTE type mismatch: expected " + expected + " but got " + actual);
        }
    }
}
