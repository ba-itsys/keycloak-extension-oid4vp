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

import COSE.AlgorithmID;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
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
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

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
        CBORObject root = CBORObject.NewMap();
        root.Add("documents", CBORObject.NewArray());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThat(verifier.isMdoc(token)).isTrue();
    }

    @Test
    void isMdoc_validMdocWithNameSpaces_returnsTrue() {
        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", CBORObject.NewMap());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

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
        CBORObject root = CBORObject.NewMap();
        root.Add("documents", CBORObject.NewArray());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty documents array");
    }

    @Test
    void verify_unknownStructure_throws() {
        CBORObject root = CBORObject.NewMap();
        root.Add("something_else", "value");
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of(signingCert)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown mDoc structure");
    }

    @Test
    void verify_noKeyMaterial_throws() {
        CBORObject item = CBORObject.NewMap();
        item.Add("elementIdentifier", "given_name");
        item.Add("elementValue", "John");

        CBORObject elements = CBORObject.NewArray();
        elements.Add(item);

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add("org.iso.18013.5.1", elements);

        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", nameSpaces);
        root.Add("docType", "org.iso.18013.5.1.mDL");

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(token, List.of()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No trusted keys available");
    }

    @Test
    void verify_signedDocument_multipleNamespaces() throws Exception {
        CBORObject item1 = CBORObject.NewMap();
        item1.Add("elementIdentifier", "given_name");
        item1.Add("elementValue", "Alice");

        CBORObject item2 = CBORObject.NewMap();
        item2.Add("elementIdentifier", "age_over_18");
        item2.Add("elementValue", true);

        CBORObject ns1 = CBORObject.NewArray();
        ns1.Add(item1);

        CBORObject ns2 = CBORObject.NewArray();
        ns2.Add(item2);

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add("org.iso.18013.5.1", ns1);
        nameSpaces.Add("org.iso.18013.5.1.aamva", ns2);

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

    // ===== Helper Methods =====

    private String buildSignedMdoc(String docType, String namespace, String[]... claimPairs) throws Exception {
        CBORObject nameSpaces = CBORObject.NewMap();
        CBORObject elements = CBORObject.NewArray();
        for (String[] pair : claimPairs) {
            CBORObject item = CBORObject.NewMap();
            item.Add("elementIdentifier", pair[0]);
            item.Add("elementValue", pair[1]);
            elements.Add(item);
        }
        nameSpaces.Add(namespace, elements);
        return buildSignedMdocWithNameSpaces(docType, nameSpaces);
    }

    private String buildSignedMdocWithStatus(
            String docType, String namespace, String statusUri, int statusIdx, String[]... claimPairs)
            throws Exception {
        CBORObject nameSpaces = CBORObject.NewMap();
        CBORObject elements = CBORObject.NewArray();
        for (String[] pair : claimPairs) {
            CBORObject item = CBORObject.NewMap();
            item.Add("elementIdentifier", pair[0]);
            item.Add("elementValue", pair[1]);
            elements.Add(item);
        }
        nameSpaces.Add(namespace, elements);

        // Build MSO with status
        CBORObject mso = CBORObject.NewMap();
        mso.Add("docType", docType);
        mso.Add("version", "1.0");

        CBORObject statusListObj = CBORObject.NewMap();
        statusListObj.Add("idx", statusIdx);
        statusListObj.Add("uri", statusUri);
        CBORObject statusObj = CBORObject.NewMap();
        statusObj.Add("status_list", statusListObj);
        mso.Add("status", statusObj);

        return buildSignedMdocWithMso(docType, nameSpaces, mso);
    }

    private String buildSignedMdocWithNameSpaces(String docType, CBORObject nameSpaces) throws Exception {
        // Build MSO (Mobile Security Object)
        CBORObject mso = CBORObject.NewMap();
        mso.Add("docType", docType);
        mso.Add("version", "1.0");

        return buildSignedMdocWithMso(docType, nameSpaces, mso);
    }

    private String buildSignedMdocWithMso(String docType, CBORObject nameSpaces, CBORObject mso) throws Exception {
        // Tag-24 wrap the MSO
        byte[] msoBytes = mso.EncodeToBytes();
        CBORObject taggedMso = CBORObject.FromObjectAndTag(CBORObject.FromObject(msoBytes), 24);

        // Create COSE_Sign1
        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), COSE.Attribute.PROTECTED);
        sign1.SetContent(taggedMso.EncodeToBytes());

        // Add x5c to unprotected header
        CBORObject x5cArray = CBORObject.NewArray();
        x5cArray.Add(CBORObject.FromObject(signingCert.getEncoded()));
        sign1.addAttribute(CBORObject.FromObject(33), x5cArray, COSE.Attribute.UNPROTECTED);

        OneKey coseKey = new OneKey(signingKeyPair.getPublic(), signingKeyPair.getPrivate());
        sign1.sign(coseKey);

        // Build document structure
        CBORObject issuerSigned = CBORObject.NewMap();
        issuerSigned.Add("nameSpaces", nameSpaces);
        issuerSigned.Add("issuerAuth", CBORObject.DecodeFromBytes(sign1.EncodeToBytes()));

        CBORObject document = CBORObject.NewMap();
        document.Add("docType", docType);
        document.Add("issuerSigned", issuerSigned);

        CBORObject documents = CBORObject.NewArray();
        documents.Add(document);

        CBORObject root = CBORObject.NewMap();
        root.Add("documents", documents);
        root.Add("version", "1.0");
        root.Add("status", CBORObject.FromObject(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());
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

        @Test
        void verifyWithSessionTranscript_oid4vpFormat_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        }

        @Test
        void verifyWithSessionTranscript_iso18013_7Format_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORObject transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

            assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
            assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        }

        @Test
        void verifyWithSessionTranscript_wrongNonce_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, "wrong-nonce", RESPONSE_URI, null))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void verifyWithSessionTranscript_isoFallbackWhenMdocNoncePresent() throws Exception {
            // Build with ISO format, verify should succeed when mdocGeneratedNonce is present
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORObject transcript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);
            String token = helper.build(transcript);

            // Verify passes — implementation should try ISO first when mdocGeneratedNonce is present
            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

            assertThat(result).isNotNull();
        }
    }

    @Nested
    class DigestVerification {

        @Test
        void verifyWithDigests_validDigests_passes() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper();
            CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            // Should pass — digests computed correctly by helper
            MdocVerificationResult result = verifier.verifyWithTrustedCerts(
                    token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null);

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

            CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("expired");
        }

        @Test
        void verify_notYetValidMso_fails() throws Exception {
            MdocDeviceResponseTestHelper helper = new MdocDeviceResponseTestHelper()
                    .validFrom(Instant.now().plus(1, ChronoUnit.DAYS))
                    .validUntil(Instant.now().plus(2, ChronoUnit.DAYS));

            CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
            String token = helper.build(transcript);

            assertThatThrownBy(() -> verifier.verifyWithTrustedCerts(
                            token, List.of(helper.issuerCert), CLIENT_ID, NONCE, RESPONSE_URI, null))
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
