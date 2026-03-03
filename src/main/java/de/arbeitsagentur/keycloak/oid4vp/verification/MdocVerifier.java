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

import COSE.OneKey;
import COSE.Sign1Message;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64URL;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.utils.StringUtil;

/**
 * Verifies mDoc (ISO 18013-5) credentials presented in a VP token.
 *
 * <p>Parses CBOR-encoded DeviceResponse structures, verifies the COSE_Sign1 issuer signature
 * (via x5chain or direct trust), and extracts namespace-prefixed claims. Also extracts MSO
 * (Mobile Security Object) status for revocation checking.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdocVerifier {

    private static final Logger LOG = Logger.getLogger(MdocVerifier.class);

    public boolean isMdoc(String token) {
        if (StringUtil.isBlank(token)) return false;
        try {
            byte[] bytes = decodeBase64(token);
            CBORObject root = CBORObject.DecodeFromBytes(bytes);
            return root.getType() == CBORType.Map && (root.ContainsKey("documents") || root.ContainsKey("nameSpaces"));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies an mDoc DeviceResponse against trusted certificates and extracts claims.
     * Performs issuer signature verification only (no device auth, digest, or validity checks).
     *
     * @param deviceResponseToken Base64-encoded CBOR DeviceResponse
     * @param trustedCertificates trusted CA certificates for COSE_Sign1 signature verification
     */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken, List<X509Certificate> trustedCertificates) {
        return verifyWithTrustedCerts(deviceResponseToken, trustedCertificates, null, null, null, null);
    }

    /**
     * Verifies an mDoc DeviceResponse with full verification: issuer signature, device authentication
     * (session transcript binding), value digest integrity, and MSO validity period.
     *
     * @see #verifyWithTrustedCerts(String, List, String, String, String, String, byte[])
     */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce) {
        return verifyWithTrustedCerts(
                deviceResponseToken, trustedCertificates, clientId, nonce, responseUri, mdocGeneratedNonce, null);
    }

    /**
     * Verifies an mDoc DeviceResponse with full verification: issuer signature, device authentication
     * (session transcript binding), value digest integrity, and MSO validity period.
     *
     * <p>When session transcript parameters ({@code clientId}, {@code nonce}, {@code responseUri})
     * are provided, device authentication is verified using the appropriate transcript format.
     * If {@code mdocGeneratedNonce} is present, ISO 18013-7 format is tried first with OID4VP 1.0
     * as fallback; otherwise only OID4VP 1.0 is used.
     *
     * @param deviceResponseToken Base64-encoded CBOR DeviceResponse
     * @param trustedCertificates trusted CA certificates for issuer signature verification
     * @param clientId the verifier's client_id (null to skip device auth)
     * @param nonce the authorization request nonce (null to skip device auth)
     * @param responseUri the response_uri from the request (null to skip device auth)
     * @param mdocGeneratedNonce nonce from JWE apu header signaling ISO 18013-7 format (may be null)
     * @param jwkThumbprint JWK thumbprint of HAIP encryption key for OID4VP 1.0 transcript (may be null)
     */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {
        List<PublicKey> trustedKeys =
                trustedCertificates.stream().map(X509Certificate::getPublicKey).toList();
        return verifyInternal(
                deviceResponseToken,
                trustedKeys,
                trustedCertificates,
                clientId,
                nonce,
                responseUri,
                mdocGeneratedNonce,
                jwkThumbprint);
    }

    private MdocVerificationResult verifyInternal(
            String deviceResponseToken,
            List<PublicKey> trustedKeys,
            List<X509Certificate> trustedCertificates,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {

        try {
            byte[] bytes = decodeBase64(deviceResponseToken);
            CBORObject root = CBORObject.DecodeFromBytes(bytes);

            CBORObject document;
            if (root.ContainsKey("documents")) {
                CBORObject documents = root.get("documents");
                if (documents.size() == 0) {
                    throw new IllegalStateException("Empty documents array in DeviceResponse");
                }
                document = documents.get(0);
            } else if (root.ContainsKey("nameSpaces")) {
                document = root;
            } else {
                throw new IllegalStateException("Unknown mDoc structure");
            }

            String docType = extractDocType(document);
            Map<String, Object> claims = extractClaims(document);

            verifyIssuerSignature(document, trustedKeys, trustedCertificates);

            // Additional verifications when session transcript parameters are provided
            CBORObject mso = parseMso(document);
            if (mso != null) {
                validateValidity(mso);
                verifyDigests(mso, document);

                boolean hasSessionTranscriptParams = clientId != null && nonce != null && responseUri != null;
                if (hasSessionTranscriptParams && document.ContainsKey("deviceSigned")) {
                    verifyDeviceAuth(
                            document, mso, docType, clientId, nonce, responseUri, mdocGeneratedNonce, jwkThumbprint);
                }
            }

            return new MdocVerificationResult(claims, docType);
        } catch (IllegalStateException e) {
            throw new IllegalStateException("mDoc verification failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new IllegalStateException("mDoc verification failed: " + e.getMessage(), e);
        }
    }

    private String extractDocType(CBORObject document) {
        if (document.ContainsKey("docType")) {
            return document.get("docType").AsString();
        }
        try {
            CBORObject mso = parseMso(document);
            if (mso != null && mso.ContainsKey("docType")) {
                return mso.get("docType").AsString();
            }
        } catch (Exception e) {
            LOG.debugf("Failed to extract docType from MSO: %s", e.getMessage());
        }
        return "mso_mdoc";
    }

    private Map<String, Object> extractClaims(CBORObject document) {
        Map<String, Object> claims = new LinkedHashMap<>();

        CBORObject nameSpaces;
        if (document.ContainsKey("issuerSigned")) {
            nameSpaces = document.get("issuerSigned").get("nameSpaces");
        } else {
            nameSpaces = document.get("nameSpaces");
        }

        if (nameSpaces == null) {
            return claims;
        }

        for (CBORObject nsKey : nameSpaces.getKeys()) {
            String namespace = nsKey.AsString();
            CBORObject elements = nameSpaces.get(nsKey);

            for (int i = 0; i < elements.size(); i++) {
                CBORObject issuerSignedItem = elements.get(i);

                // IssuerSignedItem may be tag-24 wrapped
                CBORObject item;
                if (issuerSignedItem.HasMostOuterTag(24) && issuerSignedItem.getType() == CBORType.ByteString) {
                    item = CBORObject.DecodeFromBytes(issuerSignedItem.GetByteString());
                } else if (issuerSignedItem.getType() == CBORType.Map) {
                    item = issuerSignedItem;
                } else {
                    try {
                        item = CBORObject.DecodeFromBytes(issuerSignedItem.GetByteString());
                    } catch (Exception e) {
                        continue;
                    }
                }

                if (item.ContainsKey("elementIdentifier") && item.ContainsKey("elementValue")) {
                    String elementId = item.get("elementIdentifier").AsString();
                    Object value = cborToJava(item.get("elementValue"));
                    // Namespace-prefix claims to prevent collisions
                    claims.put(namespace + "/" + elementId, value);
                }
            }
        }

        // Extract status from MSO (Mobile Security Object) if present
        extractMsoStatus(document, claims);

        return claims;
    }

    /**
     * Extracts the {@code status} field from the MSO payload inside {@code issuerAuth}.
     * The MSO may contain a {@code status.status_list} with {@code idx} and {@code uri}
     * for revocation checking via Token Status List.
     */
    private void extractMsoStatus(CBORObject document, Map<String, Object> claims) {
        try {
            CBORObject mso = parseMso(document);
            if (mso == null) {
                return;
            }

            if (mso.ContainsKey("status")) {
                Object statusValue = cborToJava(mso.get("status"));
                claims.put("status", statusValue);
                LOG.debugf("Extracted status from MSO: %s", statusValue);
            }
        } catch (Exception e) {
            LOG.debugf("Failed to extract status from MSO: %s", e.getMessage());
        }
    }

    /**
     * Parses the MSO (Mobile Security Object) from the COSE_Sign1 issuerAuth payload.
     * The payload is a CBOR ByteString that may contain a tag-24 wrapped MSO.
     */
    private CBORObject parseMso(CBORObject document) {
        CBORObject issuerSigned = document.get("issuerSigned");
        if (issuerSigned == null || !issuerSigned.ContainsKey("issuerAuth")) {
            return null;
        }

        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        CBORObject sign1;
        if (issuerAuth.getType() == CBORType.Array && issuerAuth.size() == 4) {
            sign1 = issuerAuth;
        } else {
            sign1 = CBORObject.DecodeFromBytes(issuerAuth.GetByteString());
        }

        // COSE_Sign1 element [2] is the payload: a ByteString containing the encoded MSO
        CBORObject payload = sign1.get(2);
        CBORObject decoded = CBORObject.DecodeFromBytes(payload.GetByteString());

        // MSO may be tag-24 wrapped (bstr-wrapped CBOR)
        if (decoded.HasMostOuterTag(24)) {
            return CBORObject.DecodeFromBytes(decoded.GetByteString());
        }
        return decoded;
    }

    private void verifyIssuerSignature(
            CBORObject document, List<PublicKey> trustedKeys, List<X509Certificate> trustedCertificates) {
        if ((trustedKeys == null || trustedKeys.isEmpty())
                && (trustedCertificates == null || trustedCertificates.isEmpty())) {
            throw new IllegalStateException("No trusted keys available for mDoc signature verification");
        }

        CBORObject issuerSigned = document.get("issuerSigned");
        if (issuerSigned == null || !issuerSigned.ContainsKey("issuerAuth")) {
            throw new IllegalStateException("No issuerAuth found for signature verification");
        }

        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        try {
            // IssuerAuth is a COSE_Sign1 structure: [protected, unprotected, payload, signature]
            // It may or may not be tagged with CBOR tag 18 (COSE_Sign1).
            // The COSE library requires the tag, so add it if missing.
            CBORObject sign1Cbor;
            if (issuerAuth.getType() == CBORType.Array && issuerAuth.size() == 4) {
                sign1Cbor = issuerAuth;
            } else {
                sign1Cbor = CBORObject.DecodeFromBytes(issuerAuth.GetByteString());
            }
            if (!sign1Cbor.HasMostOuterTag(18)) {
                sign1Cbor = CBORObject.FromObjectAndTag(sign1Cbor, 18);
            }
            byte[] sign1Bytes = sign1Cbor.EncodeToBytes();

            Sign1Message sign1Msg = (Sign1Message) Sign1Message.DecodeFromBytes(sign1Bytes);

            // Try x5c chain validation first (if trusted certificates are available)
            if (trustedCertificates != null && !trustedCertificates.isEmpty()) {
                PublicKey x5cKey = extractAndValidateX5cFromCose(sign1Msg, trustedCertificates);
                if (x5cKey != null) {
                    OneKey coseKey = new OneKey(x5cKey, null);
                    sign1Msg.validate(coseKey);
                    LOG.debugf("mDoc issuer signature verified via x5c chain");
                    return;
                }
            }

            // Fallback: try each trusted key directly
            Exception lastError = null;
            for (PublicKey key : trustedKeys) {
                try {
                    OneKey coseKey = new OneKey(key, null);
                    sign1Msg.validate(coseKey);
                    LOG.debugf("mDoc issuer signature verified with trusted key");
                    return;
                } catch (Exception e) {
                    lastError = e;
                }
            }

            throw new IllegalStateException("mDoc COSE_Sign1 signature verification failed: no trusted key matched"
                    + (lastError != null ? " (last error: " + lastError.getMessage() + ")" : ""));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("mDoc COSE_Sign1 signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the x5chain (label 33) from the COSE_Sign1 unprotected header,
     * validates it against trusted CA certificates, and returns the leaf certificate's public key.
     */
    private PublicKey extractAndValidateX5cFromCose(Sign1Message sign1Msg, List<X509Certificate> trustedCertificates) {
        try {
            // x5chain is COSE header label 33
            CBORObject x5chainObj = sign1Msg.findAttribute(CBORObject.FromObject(33));
            if (x5chainObj == null) {
                return null;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<>();

            if (x5chainObj.getType() == CBORType.ByteString) {
                chain.add(
                        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(x5chainObj.GetByteString())));
            } else if (x5chainObj.getType() == CBORType.Array) {
                for (int i = 0; i < x5chainObj.size(); i++) {
                    chain.add((X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(x5chainObj.get(i).GetByteString())));
                }
            }

            if (chain.isEmpty()) {
                return null;
            }

            return X5cChainValidator.validateCertChain(chain, trustedCertificates);
        } catch (Exception e) {
            LOG.debugf("Failed to extract/validate mDoc x5chain: %s", e.getMessage());
            return null;
        }
    }

    // ===== Device Authentication Verification =====

    /**
     * Verifies the device authentication signature using dual-format SessionTranscript support.
     * When {@code mdocGeneratedNonce} is present, tries ISO 18013-7 first, then falls back to OID4VP 1.0.
     */
    private void verifyDeviceAuth(
            CBORObject document,
            CBORObject mso,
            String docType,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {

        CBORObject deviceSigned = document.get("deviceSigned");
        if (deviceSigned == null || deviceSigned.getType() != CBORType.Map) {
            throw new IllegalStateException("Missing deviceSigned in DeviceResponse");
        }

        CBORObject deviceAuth = deviceSigned.get("deviceAuth");
        if (deviceAuth == null) {
            throw new IllegalStateException("Missing deviceAuth in DeviceResponse");
        }
        if (deviceAuth.getType() == CBORType.Map) {
            deviceAuth = deviceAuth.get("deviceSignature");
        }
        if (deviceAuth == null) {
            throw new IllegalStateException("Missing deviceSignature in deviceAuth");
        }

        try {
            // Decode the COSE_Sign1 device signature
            Sign1Message sign1;
            CBORObject sign1Cbor;
            if (deviceAuth.getType() == CBORType.ByteString) {
                sign1Cbor = CBORObject.DecodeFromBytes(deviceAuth.GetByteString());
            } else {
                sign1Cbor = deviceAuth;
            }
            if (!sign1Cbor.HasMostOuterTag(18)) {
                sign1Cbor = CBORObject.FromObjectAndTag(sign1Cbor, 18);
            }
            sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(sign1Cbor.EncodeToBytes());

            // Extract device key from MSO
            PublicKey deviceKey = extractDeviceKeyFromMso(mso);
            if (deviceKey == null) {
                throw new IllegalStateException("Missing deviceKeyInfo in MSO");
            }
            OneKey coseDeviceKey = new OneKey(deviceKey, null);

            // Build DeviceNameSpaces (empty map for the payload)
            CBORObject deviceNameSpaces = deviceSigned.get("nameSpaces");
            if (deviceNameSpaces == null) {
                deviceNameSpaces = CBORObject.NewMap();
            }

            // Try verification with transcript format(s)
            boolean verified = false;

            String verifiedFormat = null;

            if (mdocGeneratedNonce != null && !mdocGeneratedNonce.isBlank()) {
                // Try ISO 18013-7 first
                CBORObject isoTranscript =
                        MdocSessionTranscriptBuilder.buildIso18013_7(clientId, nonce, responseUri, mdocGeneratedNonce);
                verified = tryVerifyDeviceSignature(sign1, coseDeviceKey, isoTranscript, docType, deviceNameSpaces);
                if (verified) {
                    verifiedFormat = "ISO 18013-7";
                }

                if (!verified) {
                    // Fallback to OID4VP 1.0
                    LOG.debugf("ISO 18013-7 device auth failed, trying OID4VP 1.0 format");
                    CBORObject oid4vpTranscript =
                            MdocSessionTranscriptBuilder.buildOid4vp(clientId, nonce, responseUri, jwkThumbprint);
                    verified =
                            tryVerifyDeviceSignature(sign1, coseDeviceKey, oid4vpTranscript, docType, deviceNameSpaces);
                    if (verified) {
                        verifiedFormat = "OID4VP 1.0";
                    }
                }
            } else {
                // OID4VP 1.0 only
                CBORObject oid4vpTranscript =
                        MdocSessionTranscriptBuilder.buildOid4vp(clientId, nonce, responseUri, jwkThumbprint);
                verified = tryVerifyDeviceSignature(sign1, coseDeviceKey, oid4vpTranscript, docType, deviceNameSpaces);
                if (verified) {
                    verifiedFormat = "OID4VP 1.0";
                }
            }

            if (!verified) {
                throw new IllegalStateException("deviceAuth signature invalid");
            }
            LOG.debugf("mDoc device authentication verified using %s session transcript", verifiedFormat);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("deviceAuth verification failed: " + e.getMessage(), e);
        }
    }

    private boolean tryVerifyDeviceSignature(
            Sign1Message sign1,
            OneKey coseDeviceKey,
            CBORObject sessionTranscript,
            String docType,
            CBORObject deviceNameSpaces) {
        try {
            byte[] payload = buildDeviceAuthenticationPayload(sessionTranscript, docType, deviceNameSpaces);
            sign1.SetContent(payload);
            return sign1.validate(coseDeviceKey);
        } catch (Exception e) {
            LOG.debugf("Device signature verification attempt failed: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Builds the DeviceAuthentication payload:
     * tag-24(CBOR(["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]))
     */
    private byte[] buildDeviceAuthenticationPayload(
            CBORObject sessionTranscript, String docType, CBORObject deviceNameSpaces) {
        CBORObject deviceAuthentication = CBORObject.NewArray();
        deviceAuthentication.Add("DeviceAuthentication");
        deviceAuthentication.Add(sessionTranscript);
        deviceAuthentication.Add(docType != null ? docType : "");
        deviceAuthentication.Add(deviceNameSpaces != null ? deviceNameSpaces : CBORObject.NewMap());

        byte[] bytes = deviceAuthentication.EncodeToBytes();
        return CBORObject.FromObjectAndTag(CBORObject.FromObject(bytes), 24).EncodeToBytes();
    }

    // ===== Digest Verification =====

    /**
     * Verifies value digests in the MSO match the actual IssuerSignedItems.
     * Computes SHA-256 of raw CBOR bytes (before tag-24 unwrapping) and compares
     * against the digest map in the MSO.
     */
    private void verifyDigests(CBORObject mso, CBORObject document) {
        CBORObject valueDigests = mso.get("valueDigests");
        if (valueDigests == null || valueDigests.getType() != CBORType.Map) {
            return;
        }

        CBORObject issuerSigned = document.get("issuerSigned");
        if (issuerSigned == null) return;
        CBORObject nameSpaces = issuerSigned.get("nameSpaces");
        if (nameSpaces == null) return;

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            for (CBORObject nsKey : nameSpaces.getKeys()) {
                String namespace = nsKey.AsString();
                CBORObject elements = nameSpaces.get(nsKey);
                CBORObject nsDigests = valueDigests.get(namespace);
                if (elements == null || elements.getType() != CBORType.Array) continue;
                if (nsDigests == null || nsDigests.getType() != CBORType.Map) continue;

                for (int i = 0; i < elements.size(); i++) {
                    CBORObject element = elements.get(i);

                    // Decode the item to get its digestID
                    CBORObject item;
                    if (element.HasMostOuterTag(24) && element.getType() == CBORType.ByteString) {
                        item = CBORObject.DecodeFromBytes(element.GetByteString());
                    } else if (element.getType() == CBORType.Map) {
                        item = element;
                    } else {
                        item = CBORObject.DecodeFromBytes(element.GetByteString());
                    }

                    if (!item.ContainsKey("digestID")) continue;
                    int digestId = item.get("digestID").AsInt32Value();

                    CBORObject expectedDigest = nsDigests.get(CBORObject.FromObject(digestId));
                    if (expectedDigest == null || expectedDigest.getType() != CBORType.ByteString) {
                        throw new IllegalStateException("Missing digest for element " + digestId);
                    }

                    // Hash the raw CBOR bytes (the tag-24 wrapped form)
                    byte[] computedDigest = sha256.digest(element.EncodeToBytes());
                    if (!Arrays.equals(computedDigest, expectedDigest.GetByteString())) {
                        throw new IllegalStateException("Digest mismatch for element " + digestId);
                    }
                }
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Digest verification failed: " + e.getMessage(), e);
        }
    }

    // ===== Validity Verification =====

    /**
     * Validates the MSO validity period: {@code validFrom} ≤ now ≤ {@code validUntil}.
     */
    private void validateValidity(CBORObject mso) {
        CBORObject validityInfo = mso.get("validityInfo");
        if (validityInfo == null || validityInfo.getType() != CBORType.Map) {
            return;
        }

        Instant now = Instant.now();

        CBORObject validFrom = validityInfo.get("validFrom");
        if (validFrom != null) {
            Instant notBefore = parseInstant(validFrom);
            if (notBefore != null && notBefore.isAfter(now)) {
                throw new IllegalStateException("Credential not yet valid");
            }
        }

        CBORObject validUntil = validityInfo.get("validUntil");
        if (validUntil != null) {
            Instant notAfter = parseInstant(validUntil);
            if (notAfter != null && notAfter.isBefore(now)) {
                throw new IllegalStateException("Credential expired");
            }
        }
    }

    private Instant parseInstant(CBORObject value) {
        if (value == null) return null;
        try {
            // Tag 0 = date-time string (RFC 3339)
            if (value.HasMostOuterTag(0)) {
                return Instant.parse(value.AsString());
            }
            if (value.getType() == CBORType.TextString) {
                return Instant.parse(value.AsString());
            }
            if (value.getType() == CBORType.Integer) {
                return Instant.ofEpochSecond(value.AsInt64Value());
            }
        } catch (Exception e) {
            LOG.debugf("Failed to parse validity timestamp: %s", e.getMessage());
        }
        return null;
    }

    // ===== Device Key Extraction =====

    /**
     * Extracts the device public key from {@code mso.deviceKeyInfo.deviceKey} (COSE key format).
     * Supports EC2 keys with P-256 curve (kty=2, crv=1).
     */
    private PublicKey extractDeviceKeyFromMso(CBORObject mso) {
        CBORObject deviceKeyInfo = mso.get("deviceKeyInfo");
        if (deviceKeyInfo == null || deviceKeyInfo.getType() != CBORType.Map) {
            return null;
        }

        CBORObject deviceKey = deviceKeyInfo.get("deviceKey");
        if (deviceKey == null || deviceKey.getType() != CBORType.Map) {
            return null;
        }

        return parseCoseKey(deviceKey);
    }

    /**
     * Parses a COSE key (EC2/P-256) to a Java {@link ECPublicKey}.
     * COSE key labels: 1=kty, -1=crv, -2=x, -3=y.
     */
    private PublicKey parseCoseKey(CBORObject coseKey) {
        try {
            CBORObject kty = coseKey.get(CBORObject.FromObject(1));
            if (kty == null || kty.AsInt32Value() != 2) return null; // kty must be EC2 (2)

            CBORObject crv = coseKey.get(CBORObject.FromObject(-1));
            if (crv == null || crv.AsInt32Value() != 1) return null; // crv must be P-256 (1)

            CBORObject x = coseKey.get(CBORObject.FromObject(-2));
            CBORObject y = coseKey.get(CBORObject.FromObject(-3));
            if (x == null || y == null) return null;

            com.nimbusds.jose.jwk.ECKey jwk = new com.nimbusds.jose.jwk.ECKey.Builder(
                            Curve.P_256, Base64URL.encode(x.GetByteString()), Base64URL.encode(y.GetByteString()))
                    .build();
            return jwk.toECPublicKey();
        } catch (Exception e) {
            LOG.debugf("Failed to parse COSE key: %s", e.getMessage());
            return null;
        }
    }

    private Object cborToJava(CBORObject obj) {
        if (obj == null || obj.isNull() || obj.isUndefined()) return null;

        // Handle tagged values first (before switch on type)
        if (obj.HasMostOuterTag(0)) {
            return obj.AsString();
        }
        if (obj.HasMostOuterTag(1004)) {
            return obj.AsString();
        }

        switch (obj.getType()) {
            case TextString:
                return obj.AsString();
            case Integer:
                return obj.AsInt64Value();
            case Boolean:
                return obj.AsBoolean();
            case FloatingPoint:
                return obj.AsDouble();
            case ByteString:
                return Base64.getUrlEncoder().withoutPadding().encodeToString(obj.GetByteString());
            case Array:
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < obj.size(); i++) {
                    list.add(cborToJava(obj.get(i)));
                }
                return list;
            case Map:
                Map<String, Object> map = new LinkedHashMap<>();
                for (CBORObject key : obj.getKeys()) {
                    String keyStr = key.getType() == CBORType.TextString ? key.AsString() : key.toString();
                    map.put(keyStr, cborToJava(obj.get(key)));
                }
                return map;
            default:
                return obj.toString();
        }
    }

    private byte[] decodeBase64(String token) {
        try {
            return Base64.getUrlDecoder().decode(token);
        } catch (Exception e) {
            return Base64.getDecoder().decode(token);
        }
    }
}
