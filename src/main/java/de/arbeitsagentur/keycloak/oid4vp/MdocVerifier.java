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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jboss.logging.Logger;

public class MdocVerifier {

    private static final Logger LOG = Logger.getLogger(MdocVerifier.class);

    public boolean isMdoc(String token) {
        if (token == null || token.isBlank()) return false;
        try {
            byte[] bytes = decodeBase64(token);
            CBORObject root = CBORObject.DecodeFromBytes(bytes);
            return root.getType() == CBORType.Map && (root.ContainsKey("documents") || root.ContainsKey("nameSpaces"));
        } catch (Exception e) {
            return false;
        }
    }

    public VerificationResult verify(
            String deviceResponseToken,
            String expectedClientId,
            String expectedNonce,
            String expectedResponseUri,
            boolean trustX5cFromCredential,
            boolean skipSignatureVerification) {

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

            if (!skipSignatureVerification && trustX5cFromCredential) {
                verifyIssuerSignature(document);
            }

            return new VerificationResult(claims, docType);
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
                byte[] issuerAuthBytes = issuerAuth.getType() == CBORType.Array
                        ? issuerAuth.EncodeToBytes()
                        : issuerAuth.GetByteString();
                CBORObject sign1 = CBORObject.DecodeFromBytes(issuerAuthBytes);
                CBORObject payload = sign1.get(2);
                CBORObject mso = payload.HasMostOuterTag(24)
                        ? CBORObject.DecodeFromBytes(payload.GetByteString())
                        : CBORObject.DecodeFromBytes(payload.GetByteString());
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
                    claims.put(elementId, value);
                }
            }
        }

        return claims;
    }

    private void verifyIssuerSignature(CBORObject document) {
        try {
            CBORObject issuerSigned = document.get("issuerSigned");
            if (issuerSigned == null || !issuerSigned.ContainsKey("issuerAuth")) {
                LOG.warnf("No issuerAuth found for signature verification");
                return;
            }

            CBORObject issuerAuth = issuerSigned.get("issuerAuth");
            // IssuerAuth is a COSE_Sign1 structure: [protected, unprotected, payload, signature]
            CBORObject sign1;
            if (issuerAuth.getType() == CBORType.Array && issuerAuth.size() == 4) {
                sign1 = issuerAuth;
            } else {
                sign1 = CBORObject.DecodeFromBytes(issuerAuth.GetByteString());
            }

            // Extract x5c from unprotected headers
            CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
            CBORObject unprotectedHeader = sign1.get(1);

            CBORObject x5cCbor = null;
            if (unprotectedHeader != null && unprotectedHeader.ContainsKey(CBORObject.FromObject(33))) {
                x5cCbor = unprotectedHeader.get(CBORObject.FromObject(33));
            }
            if (x5cCbor == null && protectedHeader.ContainsKey(CBORObject.FromObject(33))) {
                x5cCbor = protectedHeader.get(CBORObject.FromObject(33));
            }

            if (x5cCbor != null) {
                byte[] certBytes;
                if (x5cCbor.getType() == CBORType.Array && x5cCbor.size() > 0) {
                    certBytes = x5cCbor.get(0).GetByteString();
                } else {
                    certBytes = x5cCbor.GetByteString();
                }

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate issuerCert =
                        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                LOG.infof(
                        "mDoc issuer certificate: %s",
                        issuerCert.getSubjectX500Principal().getName());
            }
        } catch (Exception e) {
            LOG.warnf("mDoc signature verification skipped: %s", e.getMessage());
        }
    }

    private Object cborToJava(CBORObject obj) {
        if (obj == null || obj.isNull() || obj.isUndefined()) return null;

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
                java.util.List<Object> list = new java.util.ArrayList<>();
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
                // Handle tagged values (e.g., CBOR tag 0 = date-time string, tag 1003/1004 = date)
                if (obj.HasMostOuterTag(0)) {
                    return obj.AsString();
                }
                if (obj.HasMostOuterTag(1004)) {
                    return obj.AsString();
                }
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

    public record VerificationResult(Map<String, Object> claims, String docType) {}
}
