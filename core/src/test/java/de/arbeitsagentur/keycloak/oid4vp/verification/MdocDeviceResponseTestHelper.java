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
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.COSE_ALG_ES384;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.COSE_ALG_ES512;

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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test helper for building complete mDoc DeviceResponse CBOR structures
 * with issuerAuth, deviceAuth, MSO (valueDigests, validityInfo, deviceKeyInfo).
 */
class MdocDeviceResponseTestHelper {

    record MdocAlgorithmSpec(
            String name,
            int coseAlgorithm,
            String keyAlgorithm,
            String ecCurveName,
            int coseCurveIdentifier,
            int coordinateLength,
            String certificateSignatureAlgorithm) {

        static final MdocAlgorithmSpec ES256 =
                new MdocAlgorithmSpec("ES256", COSE_ALG_ES256, "EC", "secp256r1", 1, 32, "SHA256withECDSA");
        static final MdocAlgorithmSpec ES384 =
                new MdocAlgorithmSpec("ES384", COSE_ALG_ES384, "EC", "secp384r1", 2, 48, "SHA384withECDSA");
        static final MdocAlgorithmSpec ES512 =
                new MdocAlgorithmSpec("ES512", COSE_ALG_ES512, "EC", "secp521r1", 3, 66, "SHA512withECDSA");
    }

    final KeyPair issuerKeyPair;
    final KeyPair deviceKeyPair;
    final X509Certificate issuerCert;
    final MdocAlgorithmSpec algorithm;
    String docType = "org.iso.18013.5.1.mDL";
    String namespace = "org.iso.18013.5.1";
    String[][] claimPairs = {{"given_name", "John"}, {"family_name", "Doe"}};
    Instant validFrom = Instant.now().minus(1, ChronoUnit.HOURS);
    Instant validUntil = Instant.now().plus(365, ChronoUnit.DAYS);

    MdocDeviceResponseTestHelper() throws Exception {
        this(MdocAlgorithmSpec.ES256);
    }

    MdocDeviceResponseTestHelper(MdocAlgorithmSpec algorithm) throws Exception {
        this.algorithm = algorithm;
        this.issuerKeyPair = generateKeyPair(algorithm);
        this.deviceKeyPair = generateKeyPair(algorithm);
        this.issuerCert = generateSelfSignedCert(issuerKeyPair, algorithm.certificateSignatureAlgorithm());
    }

    MdocDeviceResponseTestHelper docType(String docType) {
        this.docType = docType;
        return this;
    }

    MdocDeviceResponseTestHelper namespace(String namespace) {
        this.namespace = namespace;
        return this;
    }

    MdocDeviceResponseTestHelper claims(String[]... claimPairs) {
        this.claimPairs = claimPairs;
        return this;
    }

    MdocDeviceResponseTestHelper validFrom(Instant validFrom) {
        this.validFrom = validFrom;
        return this;
    }

    MdocDeviceResponseTestHelper validUntil(Instant validUntil) {
        this.validUntil = validUntil;
        return this;
    }

    /**
     * Builds a complete DeviceResponse with issuerAuth, deviceAuth, and MSO.
     *
     * @param sessionTranscript the session transcript CBOR to sign in deviceAuth (null to skip deviceAuth)
     */
    String build(CBORItemList sessionTranscript) throws Exception {
        // Build IssuerSignedItems and compute digests
        List<CBORItem> elements = new ArrayList<>();
        List<CBORPair> digestPairs = new ArrayList<>();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (int i = 0; i < claimPairs.length; i++) {
            CBORPairList item = new CBORPairList(List.of(
                    new CBORPair(new CBORString("digestID"), new CBORInteger(i)),
                    new CBORPair(new CBORString("random"), new CBORByteArray(new byte[] {(byte) i, 1, 2, 3})),
                    new CBORPair(new CBORString("elementIdentifier"), new CBORString(claimPairs[i][0])),
                    new CBORPair(new CBORString("elementValue"), new CBORString(claimPairs[i][1]))));

            // Wrap in tag-24 (as per ISO 18013-5)
            byte[] itemBytes = item.encode();
            CBORTaggedItem taggedItem = new CBORTaggedItem(24, new CBORByteArray(itemBytes));
            elements.add(taggedItem);

            // Digest is SHA-256 of the tag-24 wrapped bytes
            byte[] digest = sha256.digest(taggedItem.encode());
            digestPairs.add(new CBORPair(new CBORInteger(i), new CBORByteArray(digest)));
        }

        CBORPairList nameSpaces =
                new CBORPairList(List.of(new CBORPair(new CBORString(namespace), new CBORItemList(elements))));
        CBORPairList digestMap = new CBORPairList(digestPairs);

        // Build MSO
        CBORPairList mso = buildMso(digestMap);

        // Build issuerAuth (COSE_Sign1 over MSO)
        CBORItem issuerAuth = buildIssuerAuth(mso);

        // Build document
        List<CBORPair> docPairs = new ArrayList<>();
        docPairs.add(new CBORPair(new CBORString("docType"), new CBORString(docType)));
        docPairs.add(new CBORPair(
                new CBORString("issuerSigned"),
                new CBORPairList(List.of(
                        new CBORPair(new CBORString("nameSpaces"), nameSpaces),
                        new CBORPair(new CBORString("issuerAuth"), issuerAuth)))));

        // Build deviceSigned (if session transcript provided)
        if (sessionTranscript != null) {
            docPairs.add(new CBORPair(new CBORString("deviceSigned"), buildDeviceSigned(sessionTranscript)));
        }

        CBORPairList document = new CBORPairList(docPairs);

        // Wrap in DeviceResponse
        CBORPairList root = new CBORPairList(List.of(
                new CBORPair(new CBORString("documents"), new CBORItemList(document)),
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString("status"), new CBORInteger(0))));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(root.encode());
    }

    /** Builds without deviceAuth (issuer signature only). */
    String build() throws Exception {
        return build(null);
    }

    private CBORPairList buildMso(CBORPairList digestMap) {
        // validityInfo
        CBORPairList validityInfo = new CBORPairList(List.of(
                new CBORPair(new CBORString("signed"), new CBORTaggedItem(0, new CBORString(validFrom.toString()))),
                new CBORPair(new CBORString("validFrom"), new CBORTaggedItem(0, new CBORString(validFrom.toString()))),
                new CBORPair(
                        new CBORString("validUntil"), new CBORTaggedItem(0, new CBORString(validUntil.toString())))));

        // deviceKeyInfo with COSE key
        CBORPairList deviceKey = buildDeviceKey();

        CBORPairList deviceKeyInfo = new CBORPairList(List.of(new CBORPair(new CBORString("deviceKey"), deviceKey)));

        // valueDigests
        CBORPairList valueDigests = new CBORPairList(List.of(new CBORPair(new CBORString(namespace), digestMap)));

        return new CBORPairList(List.of(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString("digestAlgorithm"), new CBORString("SHA-256")),
                new CBORPair(new CBORString("docType"), new CBORString(docType)),
                new CBORPair(new CBORString("valueDigests"), valueDigests),
                new CBORPair(new CBORString("validityInfo"), validityInfo),
                new CBORPair(new CBORString("deviceKeyInfo"), deviceKeyInfo)));
    }

    private CBORItem buildIssuerAuth(CBORPairList mso) throws Exception {
        // Tag-24 wrap the MSO
        byte[] msoBytes = mso.encode();
        CBORTaggedItem taggedMso = new CBORTaggedItem(24, new CBORByteArray(msoBytes));
        byte[] payload = taggedMso.encode();

        var protectedHeader =
                new COSEProtectedHeaderBuilder().alg(algorithm.coseAlgorithm()).build();
        var unprotectedHeader =
                new COSEUnprotectedHeaderBuilder().x5chain(List.of(issuerCert)).build();

        // Build sig structure and sign
        var sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        byte[] signature = new COSESigner(issuerKeyPair.getPrivate()).sign(sigStructure, algorithm.coseAlgorithm());

        return new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(payload)
                .signature(signature)
                .build();
    }

    private CBORItem buildDeviceSigned(CBORItemList sessionTranscript) throws Exception {
        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString("DeviceAuthentication"),
                sessionTranscript,
                new CBORString(docType),
                new CBORPairList(List.of())); // empty device nameSpaces

        // Tag-24 wrap
        byte[] payload = new CBORTaggedItem(24, new CBORByteArray(deviceAuthentication.encode())).encode();

        var protectedHeader =
                new COSEProtectedHeaderBuilder().alg(algorithm.coseAlgorithm()).build();

        // Build sig structure and sign
        var sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        byte[] signature = new COSESigner(deviceKeyPair.getPrivate()).sign(sigStructure, algorithm.coseAlgorithm());

        // Build device signature COSE_Sign1
        CBORItem deviceSignature = new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .payload(payload)
                .signature(signature)
                .build();

        return new CBORPairList(List.of(
                new CBORPair(new CBORString("nameSpaces"), new CBORPairList(List.of())),
                new CBORPair(
                        new CBORString("deviceAuth"),
                        new CBORPairList(List.of(new CBORPair(new CBORString("deviceSignature"), deviceSignature))))));
    }

    private CBORPairList buildDeviceKey() {
        ECPublicKey ecPub = (ECPublicKey) deviceKeyPair.getPublic();
        byte[] x = unsignedBytes(ecPub.getW().getAffineX(), algorithm.coordinateLength());
        byte[] y = unsignedBytes(ecPub.getW().getAffineY(), algorithm.coordinateLength());
        return new CBORPairList(List.of(
                new CBORPair(new CBORInteger(1), new CBORInteger(2)),
                new CBORPair(new CBORInteger(-1), new CBORInteger(algorithm.coseCurveIdentifier())),
                new CBORPair(new CBORInteger(-2), new CBORByteArray(x)),
                new CBORPair(new CBORInteger(-3), new CBORByteArray(y))));
    }

    private static KeyPair generateKeyPair(MdocAlgorithmSpec algorithm) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm.keyAlgorithm());
        if ("EC".equals(algorithm.keyAlgorithm())) {
            keyPairGenerator.initialize(new ECGenParameterSpec(algorithm.ecCurveName()));
        }
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] unsignedBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) return bytes;
        if (bytes.length == length + 1 && bytes[0] == 0) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 1, result, 0, length);
            return result;
        }
        if (bytes.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        }
        return bytes;
    }

    static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        return generateSelfSignedCert(keyPair, "SHA256withECDSA");
    }

    static X509Certificate generateSelfSignedCert(KeyPair keyPair, String certificateSignatureAlgorithm)
            throws Exception {
        X500Principal subject = new X500Principal("CN=Test mDoc Issuer");
        Instant now = Instant.now();
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                subject,
                                BigInteger.valueOf(System.currentTimeMillis()),
                                Date.from(now.minus(1, ChronoUnit.HOURS)),
                                Date.from(now.plus(365, ChronoUnit.DAYS)),
                                subject,
                                keyPair.getPublic())
                        .build(new JcaContentSignerBuilder(certificateSignatureAlgorithm).build(keyPair.getPrivate())));
    }
}
