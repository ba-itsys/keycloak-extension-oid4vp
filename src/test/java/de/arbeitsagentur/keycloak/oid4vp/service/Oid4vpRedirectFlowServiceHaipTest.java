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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.SUPPORTED_SD_JWT_ALG_VALUES;
import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpResponseMode;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestObjectParams;
import de.arbeitsagentur.keycloak.oid4vp.domain.SignedRequestObject;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mockito;

class Oid4vpRedirectFlowServiceHaipTest {

    private Oid4vpRedirectFlowService service;
    private ECKey signingKey;
    private String signingKeyJwk;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpRedirectFlowServiceHaipTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        service = new Oid4vpRedirectFlowService(session, 300);

        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate cert = generateSelfSignedCert(signingKey);
        List<Base64> x5c = List.of(Base64.encode(cert.getEncoded()));
        signingKey = new ECKey.Builder(signingKey).x509CertChain(x5c).build();
        signingKeyJwk = signingKey.toJSONString();
    }

    @Test
    void directPostJwt_responseMode_isIncludedInRequestObject() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims.get("response_mode")).isEqualTo("direct_post.jwt");
    }

    @Test
    void directPost_responseMode_isIncludedInRequestObject() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims.get("response_mode")).isEqualTo("direct_post");
    }

    @Test
    void directPostJwt_encryptionKey_isGenerated() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        assertThat(result.encryptionKeyJson()).isNotNull();
        ECKey encKey = ECKey.parse(result.encryptionKeyJson());
        assertThat(encKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(encKey.getAlgorithm().getName()).isEqualTo("ECDH-ES");
    }

    @Test
    void directPost_encryptionKey_isNull() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST);

        assertThat(result.encryptionKeyJson()).isNull();
    }

    @Test
    void directPostJwt_clientMetadata_containsEncryptionParams() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims).containsKey("client_metadata");

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) claims.get("client_metadata");
        assertThat(meta).containsKey("jwks");
        assertThat(meta).doesNotContainKey("encrypted_response_alg_values_supported");

        @SuppressWarnings("unchecked")
        List<String> encValues = (List<String>) meta.get("encrypted_response_enc_values_supported");
        assertThat(encValues).containsExactly("A128GCM", "A256GCM");

        assertThat(meta).containsKey("vp_formats_supported");
        assertThat(meta.keySet())
                .containsExactly("jwks", "encrypted_response_enc_values_supported", "vp_formats_supported");

        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) meta.get("jwks");
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = ((List<Map<String, Object>>) jwks.get("keys")).get(0);
        assertThat(jwk.get("alg")).isEqualTo("ECDH-ES");
        assertThat(jwk.get("use")).isEqualTo("enc");
    }

    @Test
    void directPost_clientMetadata_notPresent() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims).doesNotContainKey("client_metadata");
    }

    @Test
    void directPostJwt_signingAlgorithm_isES256() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    }

    @Test
    void directPost_signingAlgorithm_isStillES256() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    }

    @Test
    void requestObject_alwaysContainsRequiredClaims() throws Exception {
        for (Oid4vpResponseMode responseMode :
                new Oid4vpResponseMode[] {Oid4vpResponseMode.DIRECT_POST_JWT, Oid4vpResponseMode.DIRECT_POST}) {
            SignedRequestObject result = buildRequestObject(responseMode);
            Map<String, Object> claims = parseClaims(result.jwt());

            assertThat(claims).containsKey("jti");
            assertThat(claims).containsKey("iat");
            assertThat(claims).containsKey("exp");
            assertThat(claims.get("iss")).isEqualTo("test-client-id");
            assertThat(claims.get("aud")).isEqualTo("https://self-issued.me/v2");
            assertThat(claims.get("client_id")).isEqualTo("test-client-id");
            assertThat(claims.get("response_type")).isEqualTo("vp_token");
            assertThat(claims.get("response_uri")).isEqualTo("https://example.com/callback");
            assertThat(claims.get("nonce")).isEqualTo("test-nonce");
            assertThat(claims.get("state")).isEqualTo("test-state");
        }
    }

    @Test
    void requestObject_typ_isOauthAuthzReqJwt() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("oauth-authz-req+jwt");
    }

    @Test
    void directPostJwt_vpFormatsSupported_containsEs256() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST_JWT);

        Map<String, Object> claims = parseClaims(result.jwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) claims.get("client_metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> vpFormats = (Map<String, Object>) meta.get("vp_formats_supported");

        assertThat(vpFormats).containsKey("dc+sd-jwt");
        assertThat(vpFormats).containsKey("mso_mdoc");

        @SuppressWarnings("unchecked")
        Map<String, Object> sdJwtFormat = (Map<String, Object>) vpFormats.get("dc+sd-jwt");
        @SuppressWarnings("unchecked")
        List<String> sdJwtAlg = (List<String>) sdJwtFormat.get("sd-jwt_alg_values");
        assertThat(sdJwtAlg).containsExactlyElementsOf(SUPPORTED_SD_JWT_ALG_VALUES);
        assertThat(sdJwtFormat.get("kb-jwt_alg_values")).isEqualTo(SUPPORTED_SD_JWT_ALG_VALUES);

        @SuppressWarnings("unchecked")
        Map<String, Object> mdocFormat = (Map<String, Object>) vpFormats.get("mso_mdoc");
        assertThat(mdocFormat.get("issuerauth_alg_values")).isEqualTo(SUPPORTED_MDOC_ISSUERAUTH_ALG_VALUES);
        assertThat(mdocFormat.get("deviceauth_alg_values")).isEqualTo(SUPPORTED_MDOC_DEVICEAUTH_ALG_VALUES);
        assertThat(mdocFormat).doesNotContainKey("alg");
    }

    @Test
    void requestObject_withoutHaip_useIdTokenSubject_setsResponseTypeAndScope() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST, true, false);
        Map<String, Object> claims = parseClaims(result.jwt());

        assertThat(claims.get("response_type")).isEqualTo("vp_token id_token");
        assertThat(claims.get("scope")).isEqualTo("openid");
    }

    @Test
    void requestObject_withHaip_useIdTokenSubject_keepsVpTokenOnly() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST, true, true);
        Map<String, Object> claims = parseClaims(result.jwt());

        assertThat(claims.get("response_type")).isEqualTo("vp_token");
        assertThat(claims).doesNotContainKey("scope");
    }

    @Test
    void requestObject_noIdTokenSubject_noScope() throws Exception {
        SignedRequestObject result = buildRequestObject(Oid4vpResponseMode.DIRECT_POST, false);
        Map<String, Object> claims = parseClaims(result.jwt());

        assertThat(claims.get("response_type")).isEqualTo("vp_token");
        assertThat(claims).doesNotContainKey("scope");
    }

    @Test
    void requestObject_manualSdJwtDcqlWithoutMeta_addsVctMetadata() throws Exception {
        SignedRequestObject result = buildRequestObject("""
                {"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["given_name"]}]}]}
                """, Oid4vpResponseMode.DIRECT_POST, false, true);

        Map<String, Object> claims = parseClaims(result.jwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> dcql = (Map<String, Object>) claims.get("dcql_query");
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credential.get("meta");
        assertThat(meta.get("vct_values")).isEqualTo(List.of("pid"));
    }

    @Test
    void requestObject_manualSdJwtDcqlPreservesExistingMeta() throws Exception {
        SignedRequestObject result = buildRequestObject("""
                {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["custom-vct"]},"claims":[{"path":["given_name"]}]}]}
                """, Oid4vpResponseMode.DIRECT_POST, false, true);

        Map<String, Object> claims = parseClaims(result.jwt());
        @SuppressWarnings("unchecked")
        Map<String, Object> dcql = (Map<String, Object>) claims.get("dcql_query");
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credential.get("meta");
        assertThat(meta.get("vct_values")).isEqualTo(List.of("custom-vct"));
    }

    private SignedRequestObject buildRequestObject(Oid4vpResponseMode responseMode) {
        return buildRequestObject(responseMode, false, true);
    }

    private SignedRequestObject buildRequestObject(Oid4vpResponseMode responseMode, boolean useIdTokenSubject) {
        return buildRequestObject(responseMode, useIdTokenSubject, true);
    }

    private SignedRequestObject buildRequestObject(
            Oid4vpResponseMode responseMode, boolean useIdTokenSubject, boolean enforceHaip) {
        return buildRequestObject(
                "{\"credentials\":[{\"id\":\"test\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"IdentityCredential\"]},\"claims\":[{\"path\":[\"sub\"]}]}]}",
                responseMode,
                useIdTokenSubject,
                enforceHaip);
    }

    private SignedRequestObject buildRequestObject(
            String dcqlQuery, Oid4vpResponseMode responseMode, boolean useIdTokenSubject, boolean enforceHaip) {
        return service.buildSignedRequestObject(new RequestObjectParams(
                dcqlQuery,
                null,
                "test-client-id",
                "x509_hash",
                "https://example.com/callback",
                "test-state",
                "test-nonce",
                null,
                signingKeyJwk,
                null,
                null,
                responseMode,
                useIdTokenSubject,
                enforceHaip));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseClaims(String jwt) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        return new ObjectMapper().readValue(signedJWT.getPayload().toString(), Map.class);
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal("CN=Test Verifier");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                publicKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.toECPrivateKey());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
