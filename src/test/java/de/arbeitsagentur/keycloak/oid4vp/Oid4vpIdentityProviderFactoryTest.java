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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

class Oid4vpIdentityProviderFactoryTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpIdentityProviderFactoryTest.class.getClassLoader());
    }

    @Test
    void metadataAndConfigProperties_areExposed() {
        Oid4vpIdentityProviderFactory factory = new Oid4vpIdentityProviderFactory();

        List<ProviderConfigProperty> properties = factory.getConfigProperties();

        assertThat(factory.getId()).isEqualTo("oid4vp");
        assertThat(factory.getName()).isEqualTo("OID4VP (Wallet Login)");
        assertThat(factory.createConfig()).isInstanceOf(Oid4vpIdentityProviderConfig.class);
        assertThat(properties).isNotEmpty();
        assertThat(properties)
                .extracting(ProviderConfigProperty::getName)
                .contains(
                        Oid4vpIdentityProviderConfig.ENFORCE_HAIP,
                        Oid4vpIdentityProviderConfig.RESPONSE_MODE,
                        Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME,
                        Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM,
                        Oid4vpIdentityProviderConfig.TRUST_LIST_URL,
                        Oid4vpIdentityProviderConfig.REQUEST_OBJECT_LIFESPAN_SECONDS);
    }

    @Test
    void resolveX509SigningKey_extractsCertificateChainAndSigningKeyFromCombinedPem() throws Exception {
        KeyPair issuerKeyPair = generateEcKeyPair();
        KeyPair leafKeyPair = generateEcKeyPair();
        X509Certificate issuerCert = createCertificate("CN=Issuer", issuerKeyPair, null, issuerKeyPair, true, null);
        X509Certificate leafCert =
                createCertificate("CN=Leaf", leafKeyPair, "CN=Issuer", issuerKeyPair, false, "wallet.example.org");
        String combinedPem = toPem(leafCert) + toPem(issuerCert) + toPem(leafKeyPair.getPrivate());

        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setX509CertificatePem(combinedPem);

        Oid4vpIdentityProviderFactory.resolveX509SigningKey(config);

        assertThat(config.getX509CertificatePem()).doesNotContain("PRIVATE KEY");
        assertThat(config.getX509CertificatePem()).contains("BEGIN CERTIFICATE");
        assertThat(config.getX509SigningKeyJwk()).contains("\"d\"");
        assertThat(config.getX509SigningKeyJwk()).contains("\"x5c\"");
    }

    @Test
    void resolveX509SigningKey_keepsExistingJwk() {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setX509SigningKeyJwk("{\"kid\":\"existing\"}");
        config.setX509CertificatePem("-----BEGIN PRIVATE KEY-----\nignored\n-----END PRIVATE KEY-----");

        Oid4vpIdentityProviderFactory.resolveX509SigningKey(config);

        assertThat(config.getX509SigningKeyJwk()).isEqualTo("{\"kid\":\"existing\"}");
    }

    @Test
    void resolveX509SigningKey_withoutPrivateKeyBlock_leavesConfigUntouched() throws Exception {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setX509CertificatePem(toPem(createCertificate("CN=Leaf", generateEcKeyPair(), null, null, false, null)));

        Oid4vpIdentityProviderFactory.resolveX509SigningKey(config);

        assertThat(config.getX509SigningKeyJwk()).isNull();
    }

    @Test
    void resolveX509SigningKey_withInvalidPrivateKey_throwsHelpfulException() throws Exception {
        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setX509CertificatePem(toPem(createCertificate("CN=Leaf", generateEcKeyPair(), null, null, false, null))
                + "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n");

        assertThatThrownBy(() -> Oid4vpIdentityProviderFactory.resolveX509SigningKey(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("signing key could not be resolved");
    }

    @Test
    void create_allowsPlainNonHaipProviderWithoutCertificateBinding() {
        KeycloakSession session = mockSession();
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias("wallet");
        model.getConfig().put(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false");
        model.getConfig().put(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "plain");

        Oid4vpIdentityProvider provider = new Oid4vpIdentityProviderFactory().create(session, model);

        assertThat(provider).isNotNull();
        assertThat(provider.getConfig().getResolvedClientIdScheme().configValue())
                .isEqualTo("plain");
    }

    private static KeycloakSession mockSession() {
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getAccessCodeLifespanLogin()).thenReturn(1800);
        when(context.getRealm()).thenReturn(realm);
        when(session.getContext()).thenReturn(context);
        return session;
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate createCertificate(
            String subjectDn,
            KeyPair subjectKeyPair,
            String issuerDn,
            KeyPair issuerKeyPair,
            boolean ca,
            String dnsSubjectAlternativeName)
            throws Exception {
        X500Principal subject = new X500Principal(subjectDn);
        X500Principal issuer = new X500Principal(issuerDn == null ? subjectDn : issuerDn);
        KeyPair signingKeyPair = issuerKeyPair == null ? subjectKeyPair : issuerKeyPair;

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 60_000),
                new Date(System.currentTimeMillis() + 86_400_000),
                subject,
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (dnsSubjectAlternativeName != null) {
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dnsSubjectAlternativeName)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(signingKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static String toPem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static String toPem(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privateKey.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }
}
