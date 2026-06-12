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
package de.arbeitsagentur.keycloak.oid4vp.it;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_SD_JWT_ALG_VALUES;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import io.github.dominikschlosser.oid4vc.CredentialFormat;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpProtocolConfigE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void loginWithX509CertChainPem() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        KeyPair caKeyPair = TestCertificates.generateEcKeyPair();
        KeyPair leafKeyPair = TestCertificates.generateEcKeyPair();
        X509Certificate caCert = TestCertificates.generateCaCert(caKeyPair);
        X509Certificate leafCert = TestCertificates.generateLeafCertWithSan(leafKeyPair, caKeyPair, "test.example.com");

        String combinedPem = TestCertificates.toPem("CERTIFICATE", leafCert.getEncoded())
                + "\n"
                + TestCertificates.toPem("CERTIFICATE", caCert.getEncoded())
                + "\n"
                + TestCertificates.toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, combinedPem,
                Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns",
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false",
                Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, ""));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        SignedJWT requestJwt = SignedJWT.parse(response.body());
        assertThat(requestJwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        // HAIP requires the self-signed trust anchor to be excluded from x5c, so only the leaf
        // remains when a leaf + self-signed CA chain is configured
        assertThat(requestJwt.getHeader().getX509CertChain()).hasSize(1);
    }

    @Test
    void loginWithCertOnlyPemAndRealmKey() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        KeyPair leafKeyPair = TestCertificates.generateEcKeyPair();
        X509Certificate leafCert =
                TestCertificates.generateLeafCertWithSan(leafKeyPair, leafKeyPair, "test.example.com");

        String certOnlyPem = TestCertificates.toPem("CERTIFICATE", leafCert.getEncoded());
        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, certOnlyPem,
                Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns",
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false",
                Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, ""));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(walletUrl).contains("request_uri=");
    }

    @Test
    void haipOverridesConfiguredClientIdSchemeToX509Hash() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "true",
                Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns",
                Oid4vpIdentityProviderConfig.RESPONSE_MODE, "direct_post"));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(extractQueryParam(walletUrl, "client_id")).startsWith("x509_hash:");

        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        SignedJWT requestJwt = SignedJWT.parse(response.body());
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("client_id")).startsWith("x509_hash:");
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("response_mode")).isEqualTo("direct_post.jwt");
    }

    @Test
    void haipRequestObjectForcesVpTokenAndAdvertisesMdocAuthAlgorithms() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "true",
                Oid4vpIdentityProviderConfig.USE_ID_TOKEN_SUBJECT, "true"));

        SignedJWT requestJwt = fetchCurrentRequestObject();
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("response_type")).isEqualTo("vp_token");
        assertThat(requestJwt.getJWTClaimsSet().getClaim("scope")).isNull();

        @SuppressWarnings("unchecked")
        Map<String, Object> clientMetadata =
                (Map<String, Object>) requestJwt.getJWTClaimsSet().getJSONObjectClaim("client_metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> vpFormats = (Map<String, Object>) clientMetadata.get("vp_formats_supported");
        @SuppressWarnings("unchecked")
        Map<String, Object> sdJwt = (Map<String, Object>) vpFormats.get("dc+sd-jwt");
        @SuppressWarnings("unchecked")
        Map<String, Object> msoMdoc = (Map<String, Object>) vpFormats.get("mso_mdoc");
        assertThat(sdJwt.get("sd-jwt_alg_values")).isEqualTo(SUPPORTED_SD_JWT_ALG_VALUES);
        assertThat(sdJwt.get("kb-jwt_alg_values")).isEqualTo(SUPPORTED_SD_JWT_ALG_VALUES);
        assertThat(((List<?>) msoMdoc.get("issuerauth_alg_values"))
                        .stream().map(value -> ((Number) value).intValue()).collect(Collectors.toList()))
                .isEqualTo(SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES);
        assertThat(((List<?>) msoMdoc.get("deviceauth_alg_values"))
                        .stream().map(value -> ((Number) value).intValue()).collect(Collectors.toList()))
                .isEqualTo(SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES);
    }

    @Test
    void trustedAuthoritiesIncludeAkiWhenEnabled() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "true",
                Oid4vpIdentityProviderConfig.TRUSTED_AUTHORITIES_MODE, "aki"));

        SignedJWT requestJwt = fetchCurrentRequestObject();
        @SuppressWarnings("unchecked")
        Map<String, Object> dcql =
                (Map<String, Object>) requestJwt.getJWTClaimsSet().getJSONObjectClaim("dcql_query");
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> trustedAuthorities =
                (List<Map<String, Object>>) credential.get("trusted_authorities");

        assertThat(trustedAuthorities).hasSize(1);
        assertThat(trustedAuthorities.get(0).get("type")).isEqualTo("aki");
        @SuppressWarnings("unchecked")
        List<String> akiValues = (List<String>) trustedAuthorities.get(0).get("values");
        assertThat(akiValues).isNotEmpty();
    }

    @Test
    void encryptedResponseModeWithoutHaipKeepsConfiguredX509SanDnsClientIdScheme() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        KeyPair caKeyPair = TestCertificates.generateEcKeyPair();
        KeyPair leafKeyPair = TestCertificates.generateEcKeyPair();
        X509Certificate caCert = TestCertificates.generateCaCert(caKeyPair);
        X509Certificate leafCert = TestCertificates.generateLeafCertWithSan(leafKeyPair, caKeyPair, "test.example.com");
        String combinedPem = TestCertificates.toPem("CERTIFICATE", leafCert.getEncoded())
                + "\n"
                + TestCertificates.toPem("CERTIFICATE", caCert.getEncoded())
                + "\n"
                + TestCertificates.toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, combinedPem,
                Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, "",
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false",
                Oid4vpIdentityProviderConfig.RESPONSE_MODE, "direct_post.jwt",
                Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns"));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(extractQueryParam(walletUrl, "client_id")).startsWith("x509_san_dns:");

        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        SignedJWT requestJwt = SignedJWT.parse(response.body());
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("client_id")).startsWith("x509_san_dns:");
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("response_mode")).isEqualTo("direct_post.jwt");
    }

    @Test
    void plainClientIdSchemeLeavesClientIdUnprefixed() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false",
                Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "plain",
                Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, "",
                Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, ""));

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        String clientId = extractQueryParam(walletUrl, "client_id");
        assertThat(clientId).isNotBlank();
        assertThat(clientId).doesNotStartWith("x509_hash:").doesNotStartWith("x509_san_dns:");

        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        SignedJWT requestJwt = SignedJWT.parse(response.body());
        assertThat(requestJwt.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo(clientId);
    }

    @Test
    void nonHaipFallsBackToKidBasedIssuerMetadataResolution() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        wallet().client().setPreferredFormat(CredentialFormat.SD_JWT);

        try {
            setIdpConfig(Map.of(
                    Oid4vpIdentityProviderConfig.TRUST_LIST_URL, wallet().pidTrustListUrl(),
                    Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false",
                    Oid4vpIdentityProviderConfig.DCQL_QUERY, buildDefaultDcqlQuery()));

            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            Oid4vpLoginFlowHelper.WalletResponse response = flow.submitToWallet(walletUrl);
            flow.waitForLoginCompletion(response);
            flow.completeFirstBrokerLoginIfNeeded("kid-metadata-user");
            flow.assertLoginSucceeded();
        } finally {
            wallet().client().clearPreferredFormat();
        }
    }

    private SignedJWT fetchCurrentRequestObject() throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();

        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(requestUri))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return SignedJWT.parse(response.body());
    }
}
