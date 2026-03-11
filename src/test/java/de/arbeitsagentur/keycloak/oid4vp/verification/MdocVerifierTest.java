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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.COSE_ALG_ES256;
import static org.assertj.core.api.Assertions.*;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.SigStructureBuilder;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class MdocVerifierTest {

    private MdocVerifier verifier;
    private KeyPair signingKeyPair;
    private X509Certificate signingCert;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new MdocVerifier();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        signingKeyPair = kpg.generateKeyPair();
        signingCert = generateSelfSignedCert(signingKeyPair);
    }

    @Test
    void isMdoc_validMdocWithDocuments_returnsTrue() {
        CBORPairList root = new CBORPairList(List.of(new CBORPair(new CBORString("documents"), new CBORItemList())));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThat(verifier.isMdoc(token)).isTrue();
    }

    @Test
    void isMdoc_validMdocWithNameSpaces_returnsTrue() {
        CBORPairList root =
                new CBORPairList(List.of(new CBORPair(new CBORString("nameSpaces"), new CBORPairList(List.of()))));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThat(verifier.isMdoc(token)).isTrue();
    }

    @Test
    void isMdoc_sdJwtString_returnsFalse() {
        assertThat(verifier.isMdoc("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~"))
                .isFalse();
    }

    @Test
    void isMdoc_null_returnsFalse() {
        assertThat(verifier.isMdoc(null)).isFalse();
    }

    @Test
    void isMdoc_blank_returnsFalse() {
        assertThat(verifier.isMdoc("")).isFalse();
    }

    @Test
    void verify_signedDocument_extractsNamespacePrefixedClaims() throws Exception {
        String token = buildSignedMdoc(
                "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "John"}, new String[] {
                    "family_name", "Doe"
                });

        MdocVerificationResult result = verifier.verifyWithTrustedCerts(token, List.of(signingCert));

        assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/family_name", "Doe");
    }

    @Test
    void verify_emptyDocumentsArray_throws() {
        CBORPairList root = new CBORPairList(List.of(new CBORPair(new CBORString("documents"), new CBORItemList())));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty documents array");
    }

    @Test
    void verify_unknownStructure_throws() {
        CBORPairList root =
                new CBORPairList(List.of(new CBORPair(new CBORString("something_else"), new CBORString("value"))));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown mDoc structure");
    }

    @Test
    void verify_noKeyMaterial_throws() {
        CBORPairList item = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("given_name")),
                new CBORPair(new CBORString("elementValue"), new CBORString("John"))));

        CBORPairList nameSpaces =
                new CBORPairList(List.of(new CBORPair(new CBORString("org.iso.18013.5.1"), new CBORItemList(item))));

        CBORPairList root = new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), nameSpaces),
                new CBORPair(new CBORString("docType"), new CBORString("org.iso.18013.5.1.mDL"))));

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No trusted keys available");
    }

    @Test
    void verify_signedDocument_multipleNamespaces() throws Exception {
        CBORPairList item1 = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("given_name")),
                new CBORPair(new CBORString("elementValue"), new CBORString("Alice"))));

        CBORPairList item2 = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("age_over_18")),
                new CBORPair(new CBORString("elementValue"), com.authlete.cbor.CBORBoolean.TRUE)));

        CBORPairList nameSpaces = new CBORPairList(List.of(
                new CBORPair(new CBORString("org.iso.18013.5.1"), new CBORItemList(item1)),
                new CBORPair(new CBORString("org.iso.18013.5.1.aamva"), new CBORItemList(item2))));

        String token = buildSignedMdocWithNameSpaces("org.iso.18013.5.1.mDL", nameSpaces);

        MdocVerificationResult result = verifier.verifyWithTrustedCerts(token, List.of(signingCert));

        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "Alice");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1.aamva/age_over_18", true);
    }

    @Test
    @SuppressWarnings("unchecked")
    void verify_signedDocumentWithMsoStatus_extractsStatusClaim() throws Exception {
        String token = buildSignedMdocWithStatus(
                "eu.europa.ec.eudi.pid.1",
                "eu.europa.ec.eudi.pid.1",
                "https://status.example.com/list/1",
                42,
                new String[] {"given_name", "Alice"});

        MdocVerificationResult result = verifier.verifyWithTrustedCerts(token, List.of(signingCert));

        assertThat(result.claims()).containsKey("status");
        Map<String, Object> status = (Map<String, Object>) result.claims().get("status");
        assertThat(status).containsKey("status_list");
        Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
        assertThat(statusList.get("uri")).isEqualTo("https://status.example.com/list/1");
        assertThat(((Number) statusList.get("idx")).intValue()).isEqualTo(42);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("supportedIssuerAlgorithms")
    void verify_supportedIssuerAlgorithms_pass(MdocDeviceResponseTestHelper.MdocAlgorithmSpec algorithm)
            throws Exception {
        MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper(algorithm);

        MdocVerificationResult result = verifier.verifyWithTrustedCerts(helper.build(), List.of(helper.issuerCert));

        assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
    }

    static Stream<MdocDeviceResponseTestHelper.MdocAlgorithmSpec> supportedIssuerAlgorithms() {
        return Stream.of(
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES256,
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES384,
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES512);
    }

    // ===== Helper Methods =====

    private String buildSignedMdoc(String docType, String namespace, String[]... claimPairs) throws Exception {
        CBORPairList nameSpaces =
                new CBORPairList(List.of(new CBORPair(new CBORString(namespace), buildElements(claimPairs))));
        return buildSignedMdocWithNameSpaces(docType, nameSpaces);
    }

    private String buildSignedMdocWithStatus(
            String docType, String namespace, String statusUri, int statusIdx, String[]... claimPairs)
            throws Exception {
        CBORPairList nameSpaces =
                new CBORPairList(List.of(new CBORPair(new CBORString(namespace), buildElements(claimPairs))));

        // Build MSO with status
        CBORPairList statusList = new CBORPairList(List.of(
                new CBORPair(new CBORString("idx"), new CBORInteger(statusIdx)),
                new CBORPair(new CBORString("uri"), new CBORString(statusUri))));
        CBORPairList statusObj = new CBORPairList(List.of(new CBORPair(new CBORString("status_list"), statusList)));
        CBORPairList mso = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString("status"), statusObj)));

        return buildSignedMdocWithMso(docType, nameSpaces, mso);
    }

    private CBORItemList buildElements(String[]... claimPairs) {
        CBORPairList[] items = new CBORPairList[claimPairs.length];
        for (int i = 0; i < claimPairs.length; i++) {
            items[i] = new CBORPairList(List.of(
                    new CBORPair(new CBORString("elementIdentifier"), new CBORString(claimPairs[i][0])),
                    new CBORPair(new CBORString("elementValue"), new CBORString(claimPairs[i][1]))));
        }
        return new CBORItemList(items);
    }

    private String buildSignedMdocWithNameSpaces(String docType, CBORPairList nameSpaces) throws Exception {
        CBORPairList mso = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("version"), new CBORString("1.0"))));
        return buildSignedMdocWithMso(docType, nameSpaces, mso);
    }

    private String buildSignedMdocWithMso(String docType, CBORPairList nameSpaces, CBORPairList mso) throws Exception {
        // Tag-24 wrap the MSO
        byte[] msoBytes = mso.encode();
        byte[] payload = new CBORTaggedItem(24, new CBORByteArray(msoBytes)).encode();

        // Build and sign COSE_Sign1
        var protectedHeader =
                new COSEProtectedHeaderBuilder().alg(COSE_ALG_ES256).build();
        var unprotectedHeader =
                new COSEUnprotectedHeaderBuilder().x5chain(List.of(signingCert)).build();

        var sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        byte[] signature = new COSESigner(signingKeyPair.getPrivate()).sign(sigStructure, COSE_ALG_ES256);

        var issuerAuth = new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(payload)
                .signature(signature)
                .build();

        // Build document structure
        CBORPairList issuerSigned = new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), nameSpaces),
                new CBORPair(new CBORString("issuerAuth"), issuerAuth)));

        CBORPairList document = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("issuerSigned"), issuerSigned)));

        CBORPairList root = new CBORPairList(List.of(
                new CBORPair(new CBORString("documents"), new CBORItemList(document)),
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString("status"), new CBORInteger(0))));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());
    }

    private static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=Test mDoc Issuer");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    // ===== Device Authentication, Digest, and Validity Tests =====

    private static final String CLIENT_ID = "https://verifier.example.com";
    private static final String NONCE = "test-nonce-12345";
    private static final String RESPONSE_URI = "https://verifier.example.com/response";
    private static final String MDOC_GENERATED_NONCE = "mdoc-nonce-67890";

    @Nested
    class DeviceAuthVerification {

        @ParameterizedTest(name = "{0}")
        @MethodSource("de.arbeitsagentur.keycloak.oid4vp.verification.MdocVerifierTest#supportedIssuerAlgorithms")
        void verifyWithSessionTranscript_oid4vpFormat_passes(MdocDeviceResponseTestHelper.MdocAlgorithmSpec algorithm)
                throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper(algorithm);
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("de.arbeitsagentur.keycloak.oid4vp.verification.MdocVerifierTest#supportedIssuerAlgorithms")
        void verifyWithSessionTranscript_iso18013_7Format_passes(
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec algorithm) throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper(algorithm);
            CBORItemList transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE, null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        }

        @Test
        void verifyWithSessionTranscript_wrongNonce_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, "wrong-nonce", RESPONSE_URI, null, null))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void verifyWithSessionTranscript_isoFallbackWhenMdocNoncePresent() throws Exception {
            // Build with ISO format, verify should succeed since OID4VP fails and falls back to ISO
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            // Verify passes — OID4VP 1.0 is tried first, then falls back to ISO 18013-7
            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE, null);

            assertThat(result).isNotNull();
        }
    }

    @Nested
    class DigestVerification {

        @Test
        void verifyWithDigests_validDigests_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            // Should pass — digests computed correctly by helper
            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.claims()).isNotEmpty();
        }
    }

    @Nested
    class ValidityVerification {

        @Test
        void verify_expiredMso_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .validFrom(Instant.now().minus(2, ChronoUnit.DAYS))
                    .validUntil(Instant.now().minus(1, ChronoUnit.DAYS));

            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        void verify_notYetValidMso_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .validFrom(Instant.now().plus(1, ChronoUnit.DAYS))
                    .validUntil(Instant.now().plus(2, ChronoUnit.DAYS));

            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not yet valid");
        }
    }

    @Nested
    class BackwardCompatibility {

        @Test
        void verify_twoParamOverload_stillWorks() throws Exception {
            // The 2-param overload should still work (skips device auth, digests, validity)
            String token = buildSignedMdoc(
                    "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "Test"}, new String[] {
                        "family_name", "User"
                    });

            MdocVerificationResult result = verifier.verifyWithTrustedCerts(token, List.of(signingCert));

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "Test");
        }
    }
}
