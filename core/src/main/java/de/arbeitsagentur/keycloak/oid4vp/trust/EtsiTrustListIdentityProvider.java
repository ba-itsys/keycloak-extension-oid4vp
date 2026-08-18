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

import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthority;
import de.arbeitsagentur.keycloak.oid4vp.domain.TrustedAuthorityType;
import de.arbeitsagentur.keycloak.oid4vp.verification.TrustListProvider;
import de.arbeitsagentur.keycloak.oid4vp.verification.X5cChainValidator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
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

    // One provider instance serves one trust resolution of one session, during which several methods
    // ask for the same certificates, once for every credential type. Trust lists without freshness
    // metadata are not cacheable across requests, so without memoising here every one of those asks
    // would be another fetch. A failed fetch resolves to an empty certificate list and is memoised
    // like any other result, so it stays empty for this instance only. A LoTE type mismatch throws
    // instead and is therefore not memoised.
    private List<X509Certificate> issuanceCertificates;
    private List<X509Certificate> revocationCertificates;
    private List<String> authorityKeyIdentifiers;

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
        // CA certificates are exposed as PKIX trust anchors through resolveX509Trust; only end entity
        // certificates are trusted directly, so a CA certificate cannot be accepted as a pinned leaf
        // on the fast path that skips end-entity certificate checks.
        return issuanceCertificates().stream()
                .filter(certificate -> !X5cChainValidator.isCaCertificate(certificate))
                .toList();
    }

    @Override
    public List<X509Certificate> revocationCertificates() {
        if (revocationCertificates == null) {
            revocationCertificates = resolveRevocationCertificates();
        }
        return revocationCertificates;
    }

    private List<X509Certificate> resolveRevocationCertificates() {
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
    public List<String> servedCredentialTypes() {
        return config.getServedCredentialTypes();
    }

    /**
     * The advertised entry of this trust domain, when the configuration names one: the trust list
     * URL as {@code etsi_tl} or the key identifiers of the issuance certificates as {@code aki}.
     * At most one entry, because both describe the same anchors and a wallet matches any
     * advertised entry. Nothing is advertised by default.
     */
    @Override
    public List<TrustedAuthority> trustedAuthorities() {
        return config.getAdvertisedTrustedAuthorityType()
                .map(type -> switch (type) {
                    case ETSI_TL ->
                        TrustedAuthority.of(TrustedAuthorityType.ETSI_TL, List.of(config.getTrustListUrl()));
                    case AKI -> TrustedAuthority.of(TrustedAuthorityType.AKI, authorityKeyIdentifiers());
                })
                .orElse(List.of());
    }

    private List<String> authorityKeyIdentifiers() {
        if (authorityKeyIdentifiers == null) {
            authorityKeyIdentifiers = resolveAuthorityKeyIdentifiers();
        }
        return authorityKeyIdentifiers;
    }

    // Advertised while building the authorization request. A cold cache fetches the trust list; an
    // unreachable one resolves to no aki entries instead of failing the request, so the login page
    // still renders and the etsi_tl URL lets the wallet resolve the list itself.
    private List<String> resolveAuthorityKeyIdentifiers() {
        Set<String> identifiers = new LinkedHashSet<>();
        if (urlTrustList != null) {
            identifiers.addAll(urlTrustList.getTrustedAuthorityKeyIdentifiers());
        }
        if (staticTrustList != null) {
            identifiers.addAll(staticTrustList.getTrustedAuthorityKeyIdentifiers());
        }
        return List.copyOf(identifiers);
    }

    @Override
    public void close() {}

    private List<X509Certificate> issuanceCertificates() {
        if (issuanceCertificates == null) {
            issuanceCertificates = resolveIssuanceCertificates();
        }
        return issuanceCertificates;
    }

    private List<X509Certificate> resolveIssuanceCertificates() {
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
