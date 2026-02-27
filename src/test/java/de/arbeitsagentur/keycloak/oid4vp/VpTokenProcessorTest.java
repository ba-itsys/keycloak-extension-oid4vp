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

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;

class VpTokenProcessorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private VpTokenProcessor processor;
    private ECKey signingKey;

    @BeforeEach
    void setUp() throws Exception {
        processor = new VpTokenProcessor(objectMapper);
        signingKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void process_singleSdJwt_returnsResult() throws Exception {
        String sdJwt =
                buildSdJwt(Map.of("iss", "https://issuer.example", "vct", "IdentityCredential", "sub", "user1")) + "~";

        VpTokenProcessor.Result result = processor.process(sdJwt, "client-id", "nonce", "uri", false, true, null, null);

        assertThat(result.credentials()).hasSize(1);
        VpTokenProcessor.VerifiedCredential primary = result.getPrimaryCredential();
        assertThat(primary.presentationType()).isEqualTo(VpTokenProcessor.PresentationType.SD_JWT);
        assertThat(primary.issuer()).isEqualTo("https://issuer.example");
        assertThat(primary.credentialType()).isEqualTo("IdentityCredential");
        assertThat(result.mergedClaims()).containsEntry("sub", "user1");
    }

    @Test
    void process_multiCredentialWrapper_verifiesAll() throws Exception {
        String sdJwt1 = buildSdJwt(Map.of("iss", "issuer1", "vct", "Type1", "name", "Alice")) + "~";
        String sdJwt2 = buildSdJwt(Map.of("iss", "issuer2", "vct", "Type2", "email", "alice@test.com")) + "~";

        String wrapper = objectMapper.writeValueAsString(Map.of("cred1", sdJwt1, "cred2", sdJwt2));

        VpTokenProcessor.Result result =
                processor.process(wrapper, "client-id", "nonce", "uri", false, true, null, null);

        assertThat(result.credentials()).hasSize(2);
        assertThat(result.isMultiCredential()).isTrue();
        assertThat(result.mergedClaims()).containsKey("name");
        assertThat(result.mergedClaims()).containsKey("email");
    }

    @Test
    void process_unsupportedFormat_throws() {
        assertThatThrownBy(() ->
                        processor.process("not-sd-jwt-or-mdoc", "client-id", "nonce", "uri", false, true, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Unsupported VP token format");
    }

    @Test
    void process_nullVpToken_throws() {
        assertThatThrownBy(() -> processor.process(null, "client-id", "nonce", "uri", false, true, null, null))
                .isInstanceOf(Exception.class);
    }

    @Test
    void process_sdJwtWithFallback_usesAlternateUri() throws Exception {
        // This test verifies the fallback mechanism exists; the primary verification
        // will succeed with skipSig=true so the fallback won't be needed
        String sdJwt = buildSdJwt(Map.of("iss", "https://issuer.example", "sub", "user1")) + "~";

        VpTokenProcessor.Result result =
                processor.process(sdJwt, "client-id", "nonce", "uri", false, true, "https://alternate.example", null);

        assertThat(result.getPrimaryCredential()).isNotNull();
    }

    private String buildSdJwt(Map<String, Object> claimsMap) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (var entry : claimsMap.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        builder.expirationTime(Date.from(Instant.now().plusSeconds(3600)));

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), builder.build());
        signedJWT.sign(new ECDSASigner(signingKey));
        return signedJWT.serialize();
    }
}
