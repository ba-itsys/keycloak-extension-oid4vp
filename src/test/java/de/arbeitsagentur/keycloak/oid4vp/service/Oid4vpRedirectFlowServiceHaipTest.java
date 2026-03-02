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

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
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
        service = new Oid4vpRedirectFlowService(session, new ObjectMapper());

        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        X509Certificate cert = generateSelfSignedCert(signingKey);
        List<Base64> x5c = List.of(Base64.encode(cert.getEncoded()));
        signingKey = new ECKey.Builder(signingKey).x509CertChain(x5c).build();
        signingKeyJwk = signingKey.toJSONString();
    }

    @Test
    void haipEnabled_responseMode_isDirectPostJwt() throws Exception {
        SignedRequestObject result = buildRequestObject(true);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims.get("response_mode")).isEqualTo("direct_post.jwt");
    }

    @Test
    void haipDisabled_responseMode_isDirectPost() throws Exception {
        SignedRequestObject result = buildRequestObject(false);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims.get("response_mode")).isEqualTo("direct_post");
    }

    @Test
    void haipEnabled_encryptionKey_isGenerated() throws Exception {
        SignedRequestObject result = buildRequestObject(true);

        assertThat(result.encryptionKeyJson()).isNotNull();
        ECKey encKey = ECKey.parse(result.encryptionKeyJson());
        assertThat(encKey.getCurve()).isEqualTo(Curve.P_256);
        assertThat(encKey.getAlgorithm().getName()).isEqualTo("ECDH-ES");
    }

    @Test
    void haipDisabled_encryptionKey_isNull() throws Exception {
        SignedRequestObject result = buildRequestObject(false);

        assertThat(result.encryptionKeyJson()).isNull();
    }

    @Test
    void haipEnabled_clientMetadata_containsEncryptionParams() throws Exception {
        SignedRequestObject result = buildRequestObject(true);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims).containsKey("client_metadata");

        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) claims.get("client_metadata");
        assertThat(meta).containsKey("jwks");

        @SuppressWarnings("unchecked")
        List<String> algValues = (List<String>) meta.get("encrypted_response_alg_values_supported");
        assertThat(algValues).containsExactly("ECDH-ES");

        @SuppressWarnings("unchecked")
        List<String> encValues = (List<String>) meta.get("encrypted_response_enc_values_supported");
        assertThat(encValues).containsExactly("A128GCM", "A256GCM");

        assertThat(meta).containsKey("vp_formats_supported");
    }

    @Test
    void haipDisabled_clientMetadata_notPresent() throws Exception {
        SignedRequestObject result = buildRequestObject(false);

        Map<String, Object> claims = parseClaims(result.jwt());
        assertThat(claims).doesNotContainKey("client_metadata");
    }

    @Test
    void haipEnabled_signingAlgorithm_isES256() throws Exception {
        SignedRequestObject result = buildRequestObject(true);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    }

    @Test
    void haipDisabled_signingAlgorithm_isStillES256() throws Exception {
        SignedRequestObject result = buildRequestObject(false);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    }

    @Test
    void requestObject_alwaysContainsRequiredClaims() throws Exception {
        for (boolean haip : new boolean[] {true, false}) {
            SignedRequestObject result = buildRequestObject(haip);
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
        SignedRequestObject result = buildRequestObject(true);

        SignedJWT jwt = SignedJWT.parse(result.jwt());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("oauth-authz-req+jwt");
    }

    @Test
    void haipEnabled_vpFormatsSupported_containsEs256() throws Exception {
        SignedRequestObject result = buildRequestObject(true);

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
        assertThat(sdJwtAlg).containsExactly("ES256");
    }

    private SignedRequestObject buildRequestObject(boolean enforceHaip) {
        return service.buildSignedRequestObject(new RequestObjectParams(
                "{\"credentials\":[{\"id\":\"test\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"IdentityCredential\"]},\"claims\":[{\"path\":[\"sub\"]}]}]}",
                null,
                "test-client-id",
                "x509_hash",
                "https://example.com/callback",
                "test-state",
                "test-nonce",
                null,
                signingKeyJwk,
                null,
                enforceHaip,
                300));
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
