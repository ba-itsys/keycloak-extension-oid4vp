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
import java.security.PublicKey;
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

            verifyIssuerSignature(document, trustedKeys);

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

        return claims;
    }

    private void verifyIssuerSignature(CBORObject document, List<PublicKey> trustedKeys) {
        if (trustedKeys == null || trustedKeys.isEmpty()) {
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

            // Try each trusted key until one succeeds
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
