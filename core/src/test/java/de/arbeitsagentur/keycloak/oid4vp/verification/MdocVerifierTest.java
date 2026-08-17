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

import com.authlete.cbor.CBORBoolean;
import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
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
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TestTrust;
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
import org.junit.jupiter.params.provider.ValueSource;

class MdocVerifierTest {

    private MdocVerifier verifier;
    private KeyPair signingKeyPair;
    private X509Certificate signingCert;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new MdocVerifier(Oid4vpIdentityProviderConfig.DEFAULT_CLOCK_SKEW_SECONDS);
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
    void verify_signedDocument_nestsClaimsUnderNamespace() throws Exception {
        String token = buildSignedMdoc(
                "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "John"}, new String[] {
                    "family_name", "Doe"
                });

        MdocVerificationResult result = verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert));

        assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(namespaceClaims(result, "org.iso.18013.5.1"))
                .containsEntry("given_name", "John")
                .containsEntry("family_name", "Doe");
    }

    // A namespace element carrying serialized JSON becomes a nested structure, so mDoc claims
    // follow the same addressing rules as SD-JWT claims. Scalar and malformed strings stay raw.
    @Test
    void verify_jsonEncodedStringElements_becomeNestedStructures() throws Exception {
        String token = buildSignedMdoc(
                "org.iso.18013.5.1.mDL",
                "org.iso.18013.5.1",
                new String[] {"address", "{\"locality\": \"London\"}"},
                new String[] {"nationalities", "[\"DE\", \"CZ\"]"},
                new String[] {"note", "just text"},
                new String[] {"number", "123"},
                new String[] {"broken", "{not json"});

        MdocVerificationResult result = verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert));

        Map<String, Object> claims = namespaceClaims(result, "org.iso.18013.5.1");
        assertThat(claims).containsEntry("address", Map.of("locality", "London"));
        assertThat(claims).containsEntry("nationalities", List.of("DE", "CZ"));
        assertThat(claims).containsEntry("note", "just text");
        assertThat(claims).containsEntry("number", "123");
        assertThat(claims).containsEntry("broken", "{not json");
    }

    @Test
    void verify_emptyDocumentsArray_throws() {
        CBORPairList root = new CBORPairList(List.of(new CBORPair(new CBORString("documents"), new CBORItemList())));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty documents array");
    }

    @Test
    void verify_unknownStructure_throws() {
        CBORPairList root =
                new CBORPairList(List.of(new CBORPair(new CBORString("something_else"), new CBORString("value"))));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown mDoc structure");
    }

    @Test
    void verify_noKeyMaterial_throws() throws Exception {
        String token =
                buildSignedMdoc("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "John"});

        assertThatThrownBy(() -> verifier.verifyIssuerSigned(token, ResolvedTrust.empty()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No trusted keys available");
    }

    // A DeviceResponse document that carries its data elements at the top level instead of inside a
    // signed issuerSigned structure must be rejected: only issuer-signed values may become claims.
    @Test
    void verify_documentWithoutIssuerSigned_throws() {
        CBORPairList item = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("given_name")),
                new CBORPair(new CBORString("elementValue"), new CBORString("John"))));
        CBORPairList nameSpaces =
                new CBORPairList(List.of(new CBORPair(new CBORString("org.iso.18013.5.1"), new CBORItemList(item))));
        CBORPairList document = new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), nameSpaces),
                new CBORPair(new CBORString("docType"), new CBORString("org.iso.18013.5.1.mDL"))));
        CBORPairList root =
                new CBORPairList(List.of(new CBORPair(new CBORString("documents"), new CBORItemList(document))));
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());

        assertThatThrownBy(() -> verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no issuerSigned structure");
    }

    @Test
    void verify_signedDocument_multipleNamespaces() throws Exception {
        CBORPairList item1 = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("given_name")),
                new CBORPair(new CBORString("elementValue"), new CBORString("Alice"))));

        CBORPairList item2 = new CBORPairList(List.of(
                new CBORPair(new CBORString("elementIdentifier"), new CBORString("age_over_18")),
                new CBORPair(new CBORString("elementValue"), CBORBoolean.TRUE)));

        CBORPairList nameSpaces = new CBORPairList(List.of(
                new CBORPair(new CBORString("org.iso.18013.5.1"), new CBORItemList(item1)),
                new CBORPair(new CBORString("org.iso.18013.5.1.aamva"), new CBORItemList(item2))));

        String token = buildSignedMdocWithNameSpaces("org.iso.18013.5.1.mDL", nameSpaces);

        MdocVerificationResult result = verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert));

        assertThat(namespaceClaims(result, "org.iso.18013.5.1")).containsEntry("given_name", "Alice");
        assertThat(namespaceClaims(result, "org.iso.18013.5.1.aamva")).containsEntry("age_over_18", true);
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

        MdocVerificationResult result = verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert));

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

        MdocVerificationResult result =
                verifier.verifyIssuerSigned(helper.build(), TestTrust.ofCertificates(helper.issuerCert));

        assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(namespaceClaims(result, "org.iso.18013.5.1")).containsEntry("given_name", "John");
    }

    static Stream<MdocDeviceResponseTestHelper.MdocAlgorithmSpec> supportedIssuerAlgorithms() {
        return Stream.of(
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES256,
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES384,
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec.ES512);
    }

    // ===== Helper Methods =====

    @SuppressWarnings("unchecked")
    private static Map<String, Object> namespaceClaims(MdocVerificationResult result, String namespace) {
        assertThat(result.claims()).containsKey(namespace);
        return (Map<String, Object>) result.claims().get(namespace);
    }

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
        CBORPairList issuerSigned = new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), nameSpaces),
                new CBORPair(new CBORString("issuerAuth"), signMso(mso))));

        CBORPairList document = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("issuerSigned"), issuerSigned)));

        return wrapInDeviceResponse(document);
    }

    private CBORItem signMso(CBORPairList mso) throws Exception {
        // Tag-24 wrap the MSO, then sign it as a COSE_Sign1 (issuerAuth).
        byte[] payload = new CBORTaggedItem(24, new CBORByteArray(mso.encode())).encode();
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
        return new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(payload)
                .signature(signature)
                .build();
    }

    private static String wrapInDeviceResponse(CBORPairList document) {
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

        private static Stream<MdocDeviceResponseTestHelper.MdocAlgorithmSpec> supportedIssuerAlgorithms() {
            return MdocVerifierTest.supportedIssuerAlgorithms();
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("supportedIssuerAlgorithms")
        void verifyWithSessionTranscript_oid4vpFormat_passes(MdocDeviceResponseTestHelper.MdocAlgorithmSpec algorithm)
                throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper(algorithm);
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyPresentation(
                    token, TestTrust.ofCertificates(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(namespaceClaims(result, "org.iso.18013.5.1")).containsEntry("given_name", "John");
        }

        /**
         * The OpenID conformance suite signs its mDLs directly with a self-signed CA profile
         * certificate, which a trust list serves as a PKIX anchor rather than a pinned end entity
         * certificate. A chain consisting of exactly that anchor is trusted without path building.
         */
        @Test
        void verifyWithSessionTranscript_signerIsTheTrustAnchorItself_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().caProfileIssuerCert();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            ResolvedTrust trust = TestTrust.ofCertificates(helper.issuerCert);
            assertThat(trust.pinnedCertificates())
                    .as("the CA profile signer certificate must not be served as a pinned certificate")
                    .isEmpty();

            MdocVerificationResult result =
                    verifier.verifyPresentation(token, trust, CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(namespaceClaims(result, "org.iso.18013.5.1")).containsEntry("given_name", "John");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("supportedIssuerAlgorithms")
        void verifyWithSessionTranscript_iso18013_7Format_passes(
                MdocDeviceResponseTestHelper.MdocAlgorithmSpec algorithm) throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper(algorithm);
            CBORItemList transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyPresentation(
                    token,
                    TestTrust.ofCertificates(helper.issuerCert),
                    CLIENT_ID,
                    NONCE,
                    RESPONSE_URI,
                    MDOC_GENERATED_NONCE,
                    null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(namespaceClaims(result, "org.iso.18013.5.1")).containsEntry("given_name", "John");
        }

        @Test
        void verifyWithSessionTranscript_wrongNonce_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            "wrong-nonce",
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void verifyWithSessionTranscript_deviceSignatureByForeignKey_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            MdocDeviceResponseTestHelper foreign = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.deviceSignedWith(foreign.deviceKeyPair).build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .as("a device signature not made with the MSO deviceKey does not bind the holder")
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("deviceAuth");
        }

        @Test
        void verifyWithSessionTranscript_tamperedDeviceSignature_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.tamperDeviceSignature().build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("deviceAuth");
        }

        @Test
        void verifyWithSessionTranscript_documentDocTypeDiffersFromMso_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.msoDocType("eu.europa.ec.eudi.pid.1").build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .as("a wallet must not relabel an issuer-signed credential through the unsigned document docType")
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("docType");
        }

        @Test
        void verifyWithSessionTranscript_isoFallbackWhenMdocNoncePresent() throws Exception {
            // Build with ISO format, verify should succeed since OID4VP fails and falls back to ISO
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            // Verify passes — OID4VP 1.0 is tried first, then falls back to ISO 18013-7
            MdocVerificationResult result = verifier.verifyPresentation(
                    token,
                    TestTrust.ofCertificates(helper.issuerCert),
                    CLIENT_ID,
                    NONCE,
                    RESPONSE_URI,
                    MDOC_GENERATED_NONCE,
                    null);

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
            MdocVerificationResult result = verifier.verifyPresentation(
                    token, TestTrust.ofCertificates(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.claims()).isNotEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"SHA-256", "SHA-384", "SHA-512"})
        void verifyWithDigests_digestAlgorithmOfTheMso_passes(String digestAlgorithm) throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().digestAlgorithm(digestAlgorithm);
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyPresentation(
                    token, TestTrust.ofCertificates(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.claims()).isNotEmpty();
        }

        @Test
        void verifyWithDigests_unsupportedDigestAlgorithm_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().declaredDigestAlgorithm("MD5");
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Unsupported mDoc digest algorithm: MD5");
        }

        @Test
        void verifyWithDigests_digestAlgorithmDifferingFromTheDigests_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .digestAlgorithm("SHA-256")
                    .declaredDigestAlgorithm("SHA-512");
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Digest mismatch");
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

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        void verifyPresentation_msoWithoutValidityInfo_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().withoutValidityInfo();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("missing the validity information");
        }

        // ISO/IEC 18013-5 makes validUntil mandatory in ValidityInfo: without it the credential
        // would never expire, so the presentation must be rejected instead of accepted forever.
        @Test
        void verifyPresentation_msoWithoutValidUntil_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().withoutValidUntil();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("missing its validUntil timestamp");
        }

        @Test
        void verifyPresentation_msoWithMalformedValidFrom_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper().rawValidFrom("not-a-timestamp");
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("unreadable validFrom timestamp");
        }

        @Test
        void verify_msoExpiredWithinTheClockSkew_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .validFrom(Instant.now().minus(2, ChronoUnit.DAYS))
                    .validUntil(Instant.now().minusSeconds(10));

            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyPresentation(
                    token, TestTrust.ofCertificates(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null);

            assertThat(result.claims()).isNotEmpty();
        }

        @Test
        void verify_notYetValidMso_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .validFrom(Instant.now().plus(1, ChronoUnit.DAYS))
                    .validUntil(Instant.now().plus(2, ChronoUnit.DAYS));

            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not yet valid");
        }
    }

    // Regression tests for the two mDoc presentation bypasses: an intercepted issuer-signed document
    // replayed without holder proof, and fabricated values that escape digest verification.
    @Nested
    class PresentationHardening {

        // Finding 1: the issuer-signed part of an mDoc is static and interceptable, so a presentation
        // without deviceSigned carries no proof that the holder key was present. It must be rejected,
        // not silently accepted by skipping device authentication.
        @Test
        void verifyPresentation_withoutDeviceSigned_isRejected() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            String issuerSignedOnly = helper.build(); // valid issuer signature and digests, but no deviceSigned

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            issuerSignedOnly,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("deviceSigned");
        }

        // Finding 2: data elements outside the signed issuerSigned structure must never become claims,
        // even when the document also carries a genuine issuerAuth. Claims are read from the same
        // issuer-signed namespaces that digest verification covers.
        @Test
        void verifyIssuerSigned_forgedTopLevelNamespace_isIgnored() throws Exception {
            String token = buildMdocWithForgedTopLevelNamespace(
                    "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "Mallory"});

            MdocVerificationResult result = verifier.verifyIssuerSigned(token, TestTrust.ofCertificates(signingCert));

            assertThat(result.claims()).doesNotContainKey("org.iso.18013.5.1");
        }

        // The same forged document offered as a presentation is rejected outright: its fabricated values
        // are not digest-covered, and value-digest verification is mandatory for a presentation.
        @Test
        void verifyPresentation_forgedTopLevelNamespace_isRejected() throws Exception {
            String token = buildMdocWithForgedTopLevelNamespace(
                    "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", new String[] {"given_name", "Mallory"});

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            token, TestTrust.ofCertificates(signingCert), CLIENT_ID, NONCE, RESPONSE_URI, null, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("value digests");
        }

        // Finding 2: tampering an issuer-signed element value breaks its MSO digest, so a presentation
        // carrying the altered value is rejected.
        @Test
        void verifyPresentation_tamperedElementValue_isRejected() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String tampered = helper.buildWithTamperedElementValue(transcript);

            assertThatThrownBy(() -> verifier.verifyPresentation(
                            tampered,
                            TestTrust.ofCertificates(helper.issuerCert),
                            CLIENT_ID,
                            NONCE,
                            RESPONSE_URI,
                            null,
                            null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Digest");
        }
    }

    // Builds a DeviceResponse whose issuerSigned namespaces are empty but which carries fabricated data
    // elements in a top-level nameSpaces sibling, i.e. values covered by neither the issuer signature nor
    // the MSO digests.
    private String buildMdocWithForgedTopLevelNamespace(String docType, String namespace, String[]... claimPairs)
            throws Exception {
        CBORPairList forged =
                new CBORPairList(List.of(new CBORPair(new CBORString(namespace), buildElements(claimPairs))));
        CBORPairList mso = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("version"), new CBORString("1.0"))));
        CBORPairList issuerSigned = new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), new CBORPairList(List.of())),
                new CBORPair(new CBORString("issuerAuth"), signMso(mso))));
        CBORPairList document = new CBORPairList(List.of(
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("nameSpaces"), forged),
                new CBORPair(new CBORString("issuerSigned"), issuerSigned)));
        return wrapInDeviceResponse(document);
    }
}
