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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.IdentityProviderModel;

/**
 * The extension's trust providers answer Keycloak's {@code validateX509Chain}, for consumers such as
 * client attestation and key attestation checks, with the rules they apply to credentials.
 */
class TrustMaterialX509ChainValidationTest {

    private static KeyPair rootKeys;
    private static KeyPair providerCaKeys;
    private static KeyPair leafKeys;
    private static X509Certificate root;
    private static X509Certificate providerCa;
    private static X509Certificate leaf;
    private static X509Certificate strangerLeaf;

    @BeforeAll
    static void certificates() throws Exception {
        CryptoIntegration.init(TrustMaterialX509ChainValidationTest.class.getClassLoader());
        rootKeys = TestCertificates.generateKeyPair();
        providerCaKeys = TestCertificates.generateKeyPair();
        leafKeys = TestCertificates.generateKeyPair();
        root = TestCertificates.issue(rootKeys, rootKeys, "CN=Root", "CN=Root", true);
        providerCa = TestCertificates.issue(providerCaKeys, rootKeys, "CN=Wallet Provider CA", "CN=Root", true);
        leaf = TestCertificates.issue(leafKeys, providerCaKeys, "CN=Wallet Provider", "CN=Wallet Provider CA", false);
        KeyPair strangerKeys = TestCertificates.generateKeyPair();
        strangerLeaf = TestCertificates.issue(strangerKeys, strangerKeys, "CN=Stranger", "CN=Stranger", false);
    }

    @Test
    void validatesAChainToAnIntermediateCaOfTheTrustList() throws Exception {
        JWK key = provider(List.of(), List.of(providerCa)).validateX509Chain(request(), x5c(leaf, providerCa), "ES256");

        assertThat(JWKParser.create(key).toPublicKey().getEncoded())
                .isEqualTo(leafKeys.getPublic().getEncoded());
    }

    @Test
    void acceptsADirectlyTrustedLeafWithoutPath() throws Exception {
        JWK key = provider(List.of(leaf), List.of()).validateX509Chain(request(), x5c(leaf), "ES256");

        assertThat(JWKParser.create(key).toPublicKey().getEncoded())
                .isEqualTo(leafKeys.getPublic().getEncoded());
    }

    @Test
    void refusesAChainThatLeadsToNoTrustedCertificate() {
        assertThatThrownBy(() -> provider(List.of(leaf), List.of(providerCa))
                        .validateX509Chain(request(), x5c(strangerLeaf), "ES256"))
                .isInstanceOf(VerificationException.class);
    }

    @Test
    void refusesAMissingChainWhenX509TrustIsConfigured() {
        assertThatThrownBy(() -> provider(List.of(), List.of(root)).validateX509Chain(request(), List.of(), "ES256"))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("x5c");
    }

    @Test
    void answersNullWithoutX509TrustLikeTheUpstreamDefault() throws Exception {
        assertThat(provider(List.of(), List.of()).validateX509Chain(request(), x5c(leaf), "ES256"))
                .isNull();
    }

    private static TrustMaterialRequest request() {
        return TrustMaterialRequest.builder().algorithm("ES256").build();
    }

    private static List<String> x5c(X509Certificate... chain) throws Exception {
        List<String> encoded = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            encoded.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        }
        return encoded;
    }

    private static Oid4vpTrustMaterialIdentityProvider<IdentityProviderModel> provider(
            List<X509Certificate> direct, List<X509Certificate> anchors) {
        return new Oid4vpTrustMaterialIdentityProvider<>() {
            @Override
            public IdentityProviderModel getConfig() {
                return new IdentityProviderModel();
            }

            @Override
            public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
                return Stream.empty();
            }

            @Override
            public List<X509Certificate> directIssuerCertificates() {
                return direct;
            }

            @Override
            public List<IssuerTrustAnchors> issuerTrustAnchors() {
                return anchors.isEmpty()
                        ? List.of()
                        : List.of(new IssuerTrustAnchors(Set.copyOf(anchors), List.of(), CrlPolicy.DEFAULT));
            }

            @Override
            public void close() {}
        };
    }
}
