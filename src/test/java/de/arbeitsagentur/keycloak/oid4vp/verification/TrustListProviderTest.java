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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TrustListProviderTest {

    private ECDSASigner signer;

    @BeforeEach
    void setUp() throws Exception {
        signer = new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate());
    }

    @AfterEach
    void clearCaches() {
        TrustListProvider.clearCache();
    }

    @Test
    void parseTrustListJwt_withExp_usesExpAsExpiry() throws Exception {
        Instant exp = Instant.now().plusSeconds(600);
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .expirationTime(Date.from(exp))
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt().getEpochSecond()).isEqualTo(exp.getEpochSecond());
    }

    @Test
    void parseTrustListJwt_withoutExp_expiresImmediately() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());
        Instant before = Instant.now();

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.expiresAt()).isBetween(before.minusSeconds(1), before.plusSeconds(1));
    }

    @Test
    void parseTrustListJwt_emptyEntitiesList_returnsEmptyKeys() throws Exception {
        String jwt = buildSignedJwt(new JWTClaimsSet.Builder()
                .claim("TrustedEntitiesList", List.of())
                .build());

        TrustListProvider.TrustListParseResult result = TrustListProvider.parseTrustListJwt(jwt);

        assertThat(result.keys()).isEmpty();
    }

    @Test
    void parseTrustListJwt_invalidJwtFormat_throws() {
        assertThatThrownBy(() -> TrustListProvider.parseTrustListJwt("not-a-jwt"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void staticKeys_returnedDirectly() {
        TrustListProvider provider = new TrustListProvider(List.of());
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    @Test
    void nullTrustListUrl_returnsEmptyKeys() {
        TrustListProvider provider = new TrustListProvider(null, null);
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    @Test
    void blankTrustListUrl_returnsEmptyKeys() {
        TrustListProvider provider = new TrustListProvider(null, "  ");
        assertThat(provider.getTrustedKeys()).isEmpty();
    }

    private String buildSignedJwt(JWTClaimsSet claims) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
