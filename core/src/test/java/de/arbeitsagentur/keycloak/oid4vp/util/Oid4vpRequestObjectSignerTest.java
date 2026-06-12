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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpClientIdScheme;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;

class Oid4vpRequestObjectSignerTest {

    private final Oid4vpRequestObjectSigner signer = new Oid4vpRequestObjectSigner();

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpRequestObjectSignerTest.class.getClassLoader());
    }

    @Test
    void x5c_excludesSelfSignedTrustAnchor() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate caCert = generateCert(caKeyPair, caKeyPair, "CN=Test CA", "CN=Test CA", true);
        X509Certificate leafCert = generateCert(leafKeyPair, caKeyPair, "CN=verifier.example.com", "CN=Test CA", false);

        SignedJWT requestObject = signRequestObject(leafKeyPair, List.of(leafCert, caCert));

        // HAIP requires that the trust anchor not appear in x5c, so only the leaf remains here
        assertThat(requestObject.getHeader().getX509CertChain()).hasSize(1);
    }

    @Test
    void x5c_keepsLeafAndIntermediateButDropsRoot() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        KeyPair intermediateKeyPair = generateKeyPair();
        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate caCert = generateCert(caKeyPair, caKeyPair, "CN=Test CA", "CN=Test CA", true);
        X509Certificate intermediateCert =
                generateCert(intermediateKeyPair, caKeyPair, "CN=Intermediate", "CN=Test CA", true);
        X509Certificate leafCert =
                generateCert(leafKeyPair, intermediateKeyPair, "CN=verifier.example.com", "CN=Intermediate", false);

        SignedJWT requestObject = signRequestObject(leafKeyPair, List.of(leafCert, intermediateCert, caCert));

        assertThat(requestObject.getHeader().getX509CertChain()).hasSize(2);
    }

    @Test
    void x5c_keepsLeafWhenChainIsLeafOnly() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate leafCert = generateCert(leafKeyPair, caKeyPair, "CN=verifier.example.com", "CN=Test CA", false);

        SignedJWT requestObject = signRequestObject(leafKeyPair, List.of(leafCert));

        assertThat(requestObject.getHeader().getX509CertChain()).hasSize(1);
    }

    private SignedJWT signRequestObject(KeyPair leafKeyPair, List<X509Certificate> chain) {
        KeyWrapper signingKey = new KeyWrapper();
        signingKey.setKid("test-kid");
        signingKey.setType(KeyType.EC);
        signingKey.setUse(KeyUse.SIG);
        signingKey.setCurve("P-256");
        signingKey.setAlgorithm("ES256");
        signingKey.setPublicKey(leafKeyPair.getPublic());
        signingKey.setPrivateKey(leafKeyPair.getPrivate());
        signingKey.setCertificateChain(chain);
        signingKey.setCertificate(chain.get(0));

        LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "verifier");
        String jwt = signer.sign(signingKey, Oid4vpClientIdScheme.X509_SAN_DNS, null, claims);
        try {
            return SignedJWT.parse(jwt);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateCert(
            KeyPair subjectKp, KeyPair issuerKp, String subjectDn, String issuerDn, boolean isCa) throws Exception {
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKp.getPrivate());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(Instant.now().minus(1, ChronoUnit.HOURS)),
                Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
                new X500Principal(subjectDn),
                subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
    }
}
