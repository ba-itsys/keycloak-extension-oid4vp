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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
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
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;

class VpTokenProcessorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private VpTokenProcessor processor;
    private ECKey signingKey;
    private X509Certificate signingCert;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(VpTokenProcessorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
        signingCert = generateSelfSignedCert(signingKey);
        TrustListProvider trustListProvider = new TrustListProvider(List.of(signingKey.toECPublicKey()));
        processor = new VpTokenProcessor(objectMapper, new StatusListVerifier(), trustListProvider);
    }

    @Test
    void process_singleSdJwt_returnsResult() throws Exception {
        String sdJwt =
                buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user1")) + "~";

        VpTokenResult result = processor.process(sdJwt, "client-id", "nonce", "uri", null, null);

        assertThat(result.credentials()).hasSize(1);
        VerifiedCredential primary = result.getPrimaryCredential();
        assertThat(primary.presentationType()).isEqualTo(PresentationType.SD_JWT);
        assertThat(primary.issuer()).isEqualTo("https://issuer.example");
        assertThat(primary.credentialType()).isEqualTo("IdentityCredential");
        assertThat(result.mergedClaims()).containsEntry("sub", "user1");
    }

    @Test
    void process_multiCredentialWrapper_verifiesAll() throws Exception {
        String sdJwt1 = buildSdJwt(Map.of("iss", "issuer1", "vct", "Type1", "name", "Alice")) + "~";
        String sdJwt2 = buildSdJwt(Map.of("iss", "issuer2", "vct", "Type2", "email", "alice@test.com")) + "~";

        String wrapper = objectMapper.writeValueAsString(Map.of("cred1", sdJwt1, "cred2", sdJwt2));

        VpTokenResult result = processor.process(wrapper, "client-id", "nonce", "uri", null, null);

        assertThat(result.credentials()).hasSize(2);
        assertThat(result.isMultiCredential()).isTrue();
        assertThat(result.mergedClaims()).containsKey("name");
        assertThat(result.mergedClaims()).containsKey("email");
    }

    @Test
    void process_unsupportedFormat_throws() {
        assertThatThrownBy(() -> processor.process("not-sd-jwt-or-mdoc", "client-id", "nonce", "uri", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Unsupported VP token format");
    }

    @Test
    void process_nullVpToken_throws() {
        assertThatThrownBy(() -> processor.process(null, "client-id", "nonce", "uri", null, null))
                .isInstanceOf(Exception.class);
    }

    @Test
    void process_sdJwtWithFallback_usesAlternateUri() throws Exception {
        String sdJwt = buildSdJwt(Map.of("iss", "https://issuer.example", "sub", "user1")) + "~";

        VpTokenResult result = processor.process(sdJwt, "client-id", "nonce", "uri", "https://alternate.example", null);

        assertThat(result.getPrimaryCredential()).isNotNull();
    }

    // ===== Helper Methods =====

    private JWSHeader buildHeaderWithX5c() throws Exception {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(signingCert.getEncoded())))
                .build();
    }

    private String buildSdJwt(Map<String, Object> claimsMap) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        Instant now = Instant.now();
        builder.issueTime(Date.from(now));
        builder.notBeforeTime(Date.from(now));
        builder.expirationTime(Date.from(now.plusSeconds(3600)));

        SignedJWT signedJWT = new SignedJWT(buildHeaderWithX5c(), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }

    private static X509Certificate generateSelfSignedCert(ECKey ecKey) throws Exception {
        ECPublicKey publicKey = ecKey.toECPublicKey();
        X500Principal subject = new X500Principal("CN=Test SD-JWT Issuer");
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
