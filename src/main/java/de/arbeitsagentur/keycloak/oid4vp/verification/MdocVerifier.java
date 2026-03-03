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
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.utils.StringUtil;

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

    public MdocVerificationResult verify(String deviceResponseToken, List<PublicKey> trustedKeys) {
        // Legacy method for backward compatibility
        return verifyWithCertificates(deviceResponseToken, trustedKeys, List.of());
    }

    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken, List<X509Certificate> trustedCertificates) {
        List<PublicKey> trustedKeys =
                trustedCertificates.stream().map(X509Certificate::getPublicKey).toList();
        return verifyWithCertificates(deviceResponseToken, trustedKeys, trustedCertificates);
    }

    private MdocVerificationResult verifyWithCertificates(
            String deviceResponseToken, List<PublicKey> trustedKeys, List<X509Certificate> trustedCertificates) {

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

            return new MdocVerificationResult(claims, docType);
        } catch (Exception e) {
            throw new IllegalStateException("mDoc verification failed: " + e.getMessage(), e);
        }
    }

    private String extractDocType(CBORObject document) {
        if (document.ContainsKey("docType")) {
            return document.get("docType").AsString();
        }

        // Try to extract from MSO
        CBORObject issuerSigned = document.get("issuerSigned");
        if (issuerSigned != null && issuerSigned.ContainsKey("issuerAuth")) {
            try {
                CBORObject issuerAuth = issuerSigned.get("issuerAuth");
                CBORObject sign1;
                if (issuerAuth.getType() == CBORType.Array && issuerAuth.size() == 4) {
                    sign1 = issuerAuth;
                } else {
                    sign1 = CBORObject.DecodeFromBytes(issuerAuth.GetByteString());
                }
                CBORObject payload = sign1.get(2);
                CBORObject mso;
                if (payload.HasMostOuterTag(24)) {
                    mso = CBORObject.DecodeFromBytes(
                            CBORObject.DecodeFromBytes(payload.EncodeToBytes()).GetByteString());
                } else {
                    mso = CBORObject.DecodeFromBytes(payload.GetByteString());
                }
                if (mso.ContainsKey("docType")) {
                    return mso.get("docType").AsString();
                }
            } catch (Exception e) {
                LOG.debugf("Failed to extract docType from MSO: %s", e.getMessage());
            }
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
                // Single certificate
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

            X509Certificate leaf = chain.get(0);
            LOG.debugf(
                    "mDoc x5chain leaf certificate: %s",
                    leaf.getSubjectX500Principal().getName());

            // Walk up the chain
            for (int i = 0; i < chain.size() - 1; i++) {
                chain.get(i).verify(chain.get(i + 1).getPublicKey());
            }

            // Verify top of chain is signed by a trusted certificate
            X509Certificate topOfChain = chain.get(chain.size() - 1);
            for (X509Certificate trusted : trustedCertificates) {
                try {
                    topOfChain.verify(trusted.getPublicKey());
                    LOG.debugf(
                            "mDoc x5chain anchored by trusted certificate: %s",
                            trusted.getSubjectX500Principal().getName());
                    return leaf.getPublicKey();
                } catch (Exception ignored) {
                    // Try next
                }
            }

            LOG.debug("mDoc x5chain not anchored by any trusted certificate");
            return null;
        } catch (Exception e) {
            LOG.debugf("Failed to extract/validate mDoc x5chain: %s", e.getMessage());
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
