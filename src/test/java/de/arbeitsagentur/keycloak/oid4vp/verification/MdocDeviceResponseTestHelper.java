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

import COSE.AlgorithmID;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test helper for building complete mDoc DeviceResponse CBOR structures
 * with issuerAuth, deviceAuth, MSO (valueDigests, validityInfo, deviceKeyInfo).
 */
class MdocDeviceResponseTestHelper {

    final KeyPair issuerKeyPair;
    final KeyPair deviceKeyPair;
    final X509Certificate issuerCert;
    String docType = "org.iso.18013.5.1.mDL";
    String namespace = "org.iso.18013.5.1";
    String[][] claimPairs = {{"given_name", "John"}, {"family_name", "Doe"}};
    Instant validFrom = Instant.now().minus(1, ChronoUnit.HOURS);
    Instant validUntil = Instant.now().plus(365, ChronoUnit.DAYS);

    MdocDeviceResponseTestHelper() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        this.issuerKeyPair = kpg.generateKeyPair();
        this.deviceKeyPair = kpg.generateKeyPair();
        this.issuerCert = generateSelfSignedCert(issuerKeyPair);
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
    String build(CBORObject sessionTranscript) throws Exception {
        // Build IssuerSignedItems and compute digests
        CBORObject elements = CBORObject.NewArray();
        CBORObject digestMap = CBORObject.NewMap();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (int i = 0; i < claimPairs.length; i++) {
            CBORObject item = CBORObject.NewMap();
            item.Add("digestID", i);
            item.Add("random", CBORObject.FromObject(new byte[] {(byte) i, 1, 2, 3}));
            item.Add("elementIdentifier", claimPairs[i][0]);
            item.Add("elementValue", claimPairs[i][1]);

            // Wrap in tag-24 (as per ISO 18013-5)
            byte[] itemBytes = item.EncodeToBytes();
            CBORObject taggedItem = CBORObject.FromObjectAndTag(CBORObject.FromObject(itemBytes), 24);
            elements.Add(taggedItem);

            // Digest is SHA-256 of the tag-24 wrapped bytes (raw CBOR bytes before unwrap)
            byte[] digest = sha256.digest(taggedItem.EncodeToBytes());
            digestMap.Add(CBORObject.FromObject(i), digest);
        }

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add(namespace, elements);

        // Build MSO
        CBORObject mso = buildMso(digestMap);

        // Build issuerAuth (COSE_Sign1 over MSO)
        CBORObject issuerAuth = buildIssuerAuth(mso);

        // Build issuerSigned
        CBORObject issuerSigned = CBORObject.NewMap();
        issuerSigned.Add("nameSpaces", nameSpaces);
        issuerSigned.Add("issuerAuth", issuerAuth);

        // Build document
        CBORObject document = CBORObject.NewMap();
        document.Add("docType", docType);
        document.Add("issuerSigned", issuerSigned);

        // Build deviceSigned (if session transcript provided)
        if (sessionTranscript != null) {
            CBORObject deviceSigned = buildDeviceSigned(sessionTranscript);
            document.Add("deviceSigned", deviceSigned);
        }

        // Wrap in DeviceResponse
        CBORObject documents = CBORObject.NewArray();
        documents.Add(document);

        CBORObject root = CBORObject.NewMap();
        root.Add("documents", documents);
        root.Add("version", "1.0");
        root.Add("status", CBORObject.FromObject(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());
    }

    /** Builds without deviceAuth (issuer signature only). */
    String build() throws Exception {
        return build(null);
    }

    private CBORObject buildMso(CBORObject digestMap) {
        CBORObject mso = CBORObject.NewMap();
        mso.Add("version", "1.0");
        mso.Add("digestAlgorithm", "SHA-256");
        mso.Add("docType", docType);

        // valueDigests
        CBORObject valueDigests = CBORObject.NewMap();
        valueDigests.Add(namespace, digestMap);
        mso.Add("valueDigests", valueDigests);

        // validityInfo
        CBORObject validityInfo = CBORObject.NewMap();
        validityInfo.Add("signed", CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validityInfo.Add("validFrom", CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validityInfo.Add("validUntil", CBORObject.FromObjectAndTag(validUntil.toString(), 0));
        mso.Add("validityInfo", validityInfo);

        // deviceKeyInfo with COSE key
        ECPublicKey ecPub = (ECPublicKey) deviceKeyPair.getPublic();
        byte[] x = unsignedBytes(ecPub.getW().getAffineX(), 32);
        byte[] y = unsignedBytes(ecPub.getW().getAffineY(), 32);

        CBORObject deviceKey = CBORObject.NewMap();
        deviceKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
        deviceKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
        deviceKey.Add(CBORObject.FromObject(-2), x); // x
        deviceKey.Add(CBORObject.FromObject(-3), y); // y

        CBORObject deviceKeyInfo = CBORObject.NewMap();
        deviceKeyInfo.Add("deviceKey", deviceKey);
        mso.Add("deviceKeyInfo", deviceKeyInfo);

        return mso;
    }

    private CBORObject buildIssuerAuth(CBORObject mso) throws Exception {
        // Tag-24 wrap the MSO
        byte[] msoBytes = mso.EncodeToBytes();
        CBORObject taggedMso = CBORObject.FromObjectAndTag(CBORObject.FromObject(msoBytes), 24);

        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), COSE.Attribute.PROTECTED);
        sign1.SetContent(taggedMso.EncodeToBytes());

        // Add x5c
        CBORObject x5cArray = CBORObject.NewArray();
        x5cArray.Add(CBORObject.FromObject(issuerCert.getEncoded()));
        sign1.addAttribute(CBORObject.FromObject(33), x5cArray, COSE.Attribute.UNPROTECTED);

        OneKey coseKey = new OneKey(issuerKeyPair.getPublic(), issuerKeyPair.getPrivate());
        sign1.sign(coseKey);

        return CBORObject.DecodeFromBytes(sign1.EncodeToBytes());
    }

    private CBORObject buildDeviceSigned(CBORObject sessionTranscript) throws Exception {
        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
        CBORObject deviceAuthentication = CBORObject.NewArray();
        deviceAuthentication.Add("DeviceAuthentication");
        deviceAuthentication.Add(sessionTranscript);
        deviceAuthentication.Add(docType);
        deviceAuthentication.Add(CBORObject.NewMap()); // empty device nameSpaces

        // Tag-24 wrap (external data for COSE_Sign1)
        byte[] deviceAuthBytes = CBORObject.FromObjectAndTag(
                        CBORObject.FromObject(deviceAuthentication.EncodeToBytes()), 24)
                .EncodeToBytes();

        // Create COSE_Sign1 with detached payload
        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), COSE.Attribute.PROTECTED);
        sign1.SetContent(deviceAuthBytes);

        OneKey coseKey = new OneKey(deviceKeyPair.getPublic(), deviceKeyPair.getPrivate());
        sign1.sign(coseKey);

        CBORObject deviceSignature = CBORObject.DecodeFromBytes(sign1.EncodeToBytes());

        CBORObject deviceAuth = CBORObject.NewMap();
        deviceAuth.Add("deviceSignature", deviceSignature);

        CBORObject deviceSigned = CBORObject.NewMap();
        deviceSigned.Add("nameSpaces", CBORObject.NewMap());
        deviceSigned.Add("deviceAuth", deviceAuth);

        return deviceSigned;
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
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
