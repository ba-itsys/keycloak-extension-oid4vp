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

import com.authlete.cbor.CBORBoolean;
import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORDouble;
import com.authlete.cbor.CBORFloat;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORLong;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEKey;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import de.arbeitsagentur.keycloak.oid4vp.domain.MdocVerificationResult;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.utils.StringUtil;

/**
 * Verifies mDoc (ISO 18013-5) credentials presented in a VP token.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdocVerifier {

    private static final Logger LOG = Logger.getLogger(MdocVerifier.class);
    private static final int CBOR_TAG_DATE = 1004;

    public boolean isMdoc(String token) {
        if (StringUtil.isBlank(token)) return false;
        try {
            CBORItem root = decodeCbor(decodeBase64(token));
            if (!(root instanceof CBORPairList map)) return false;
            return val(map, "documents") != null || val(map, "nameSpaces") != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** Issuer signature verification only (no device auth, digest, or validity checks). */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken, List<X509Certificate> trustedCertificates) {
        return verifyWithTrustedCerts(deviceResponseToken, trustedCertificates, null, null, null, null, null);
    }

    /**
     * Full verification: issuer signature, device authentication, value digests, MSO validity.
     * OID4VP 1.0 transcript is tried first; ISO 18013-7 as fallback when mdocGeneratedNonce is present.
     */
    public MdocVerificationResult verifyWithTrustedCerts(
            String deviceResponseToken,
            List<X509Certificate> trustedCertificates,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {
        try {
            CBORPairList document = parseDocument(decodeBase64(deviceResponseToken));
            CBORPairList mso = parseMso(document);

            String docType = str(document, "docType");
            if (docType == null) docType = mso != null ? str(mso, "docType") : null;
            if (docType == null) docType = "mso_mdoc";

            Map<String, Object> claims = extractClaims(document, mso);
            verifyIssuerSignature(document, trustedCertificates);

            if (mso != null) {
                validateValidity(mso);
                verifyDigests(mso, document);
                if (clientId != null && nonce != null && responseUri != null && val(document, "deviceSigned") != null) {
                    verifyDeviceAuth(
                            document, mso, docType, clientId, nonce, responseUri, mdocGeneratedNonce, jwkThumbprint);
                }
            }

            return new MdocVerificationResult(claims, docType);
        } catch (Exception e) {
            throw wrapIfNeeded(e, "mDoc verification failed: ");
        }
    }

    private CBORPairList parseDocument(byte[] bytes) {
        CBORItem root = decodeCbor(bytes);
        if (!(root instanceof CBORPairList rootMap)) throw new IllegalStateException("Unknown mDoc structure");

        CBORItem docs = val(rootMap, "documents");
        if (docs instanceof CBORItemList docsList) {
            if (docsList.getItems() == null || docsList.getItems().isEmpty()) {
                throw new IllegalStateException("Empty documents array");
            }
            if (docsList.getItems().get(0) instanceof CBORPairList doc) return doc;
            throw new IllegalStateException("Invalid document entry");
        }
        if (val(rootMap, "nameSpaces") != null) return rootMap;
        throw new IllegalStateException("Unknown mDoc structure");
    }

    private Map<String, Object> extractClaims(CBORPairList document, CBORPairList mso) {
        Map<String, Object> claims = new LinkedHashMap<>();

        CBORPairList nameSpaces = map(map(document, "issuerSigned"), "nameSpaces");
        if (nameSpaces == null) nameSpaces = map(document, "nameSpaces");
        if (nameSpaces == null) return claims;

        for (var nsPair : nameSpaces.getPairs()) {
            String namespace = stringValue(nsPair.getKey());
            if (namespace != null && nsPair.getValue() instanceof CBORItemList elementsList) {
                addNamespaceClaims(claims, namespace, elementsList);
            }
        }

        if (mso != null) {
            CBORItem status = val(mso, "status");
            if (status != null) claims.put("status", cborToJava(status));
        }
        return claims;
    }

    private void addNamespaceClaims(Map<String, Object> claims, String namespace, CBORItemList elementsList) {
        for (CBORItem element : elementsList.getItems()) {
            CBORPairList item = unwrapTag24(element);
            if (item != null) {
                String elementId = str(item, "elementIdentifier");
                if (elementId != null) {
                    claims.put(namespace + "/" + elementId, cborToJava(val(item, "elementValue")));
                }
            }
        }
    }

    /**
     * CBOR tag 24 means "encoded CBOR data item": the tag content is a byte string whose bytes
     * contain another CBOR structure. mdoc issuer-signed items commonly use this wrapper, so we
     * decode the inner bytes before reading fields like {@code elementIdentifier} or
     * {@code digestID}.
     */
    private CBORPairList unwrapTag24(CBORItem element) {
        if (element instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 24) {
            CBORItem content = tagged.getTagContent();
            if (content instanceof CBORByteArray bstr) return asMap(decodeCbor(bstr.getValue()));
        }
        if (element instanceof CBORPairList m) return m;
        if (element instanceof CBORByteArray bstr) return asMap(decodeCbor(bstr.getValue()));
        return null;
    }

    private CBORPairList parseMso(CBORPairList document) {
        CBORItem issuerAuth = val(map(document, "issuerSigned"), "issuerAuth");
        if (issuerAuth == null) return null;

        CBORItem payload = buildCoseSign1(issuerAuth).getPayload();
        if (payload == null) return null;

        byte[] bytes = payload instanceof CBORByteArray bstr ? bstr.getValue() : payload.encode();
        CBORItem decoded = decodeCbor(bytes);

        if (decoded instanceof CBORTaggedItem tagged
                && tagged.getTagNumber().intValue() == 24
                && tagged.getTagContent() instanceof CBORByteArray bstr) {
            return asMap(decodeCbor(bstr.getValue()));
        }
        return asMap(decoded);
    }

    private void verifyIssuerSignature(CBORPairList document, List<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            throw new IllegalStateException("No trusted keys available for mDoc signature verification");
        }

        CBORItem issuerAuth = val(map(document, "issuerSigned"), "issuerAuth");
        if (issuerAuth == null) throw new IllegalStateException("No issuerAuth found");

        try {
            COSESign1 sign1 = buildCoseSign1(issuerAuth);

            List<X509Certificate> x5chain = extractX5Chain(sign1);
            if (x5chain != null && !x5chain.isEmpty()) {
                PublicKey leafKey = X5cChainValidator.validateCertChain(x5chain, trustedCertificates);
                if (leafKey != null && new COSEVerifier(leafKey).verify(sign1)) return;
            }

            for (X509Certificate cert : trustedCertificates) {
                try {
                    if (new COSEVerifier(cert.getPublicKey()).verify(sign1)) return;
                } catch (Exception ignored) {
                }
            }
            throw new IllegalStateException("No trusted key matched");
        } catch (Exception e) {
            throw wrapIfNeeded(e, "Issuer signature verification failed: ");
        }
    }

    private List<X509Certificate> extractX5Chain(COSESign1 sign1) {
        try {
            if (sign1.getUnprotectedHeader() != null) {
                var chain = sign1.getUnprotectedHeader().getX5Chain();
                if (chain != null && !chain.isEmpty()) return chain;
            }
            if (sign1.getProtectedHeader() != null) {
                var chain = sign1.getProtectedHeader().getX5Chain();
                if (chain != null && !chain.isEmpty()) return chain;
            }
        } catch (Exception e) {
            LOG.debugf("Failed to extract x5chain: %s", e.getMessage());
        }
        return null;
    }

    private void verifyDeviceAuth(
            CBORPairList document,
            CBORPairList mso,
            String docType,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {

        COSESign1 deviceSign1 = extractDeviceSignature(document);
        PublicKey deviceKey = extractDeviceKey(mso);
        CBORItem deviceNameSpaces = val(map(document, "deviceSigned"), "nameSpaces");
        if (deviceNameSpaces == null) deviceNameSpaces = new CBORPairList(List.of());

        // Try OID4VP 1.0 first (default)
        CBORItemList oid4vpTranscript =
                MdocSessionTranscriptBuilder.buildOid4vp(clientId, nonce, responseUri, jwkThumbprint);
        if (tryVerifyDevice(deviceSign1, deviceKey, oid4vpTranscript, docType, deviceNameSpaces)) {
            LOG.debug("Device auth verified using OID4VP 1.0 transcript");
            return;
        }

        // Fallback to ISO 18013-7 if mdocGeneratedNonce is present
        if (mdocGeneratedNonce != null && !mdocGeneratedNonce.isBlank()) {
            CBORItemList isoTranscript =
                    MdocSessionTranscriptBuilder.buildIso18013_7(clientId, nonce, responseUri, mdocGeneratedNonce);
            if (tryVerifyDevice(deviceSign1, deviceKey, isoTranscript, docType, deviceNameSpaces)) {
                LOG.debug("Device auth verified using ISO 18013-7 transcript");
                return;
            }
        }

        throw new IllegalStateException("deviceAuth signature invalid");
    }

    private COSESign1 extractDeviceSignature(CBORPairList document) {
        CBORPairList deviceSigned = map(document, "deviceSigned");
        if (deviceSigned == null) throw new IllegalStateException("Missing deviceSigned");

        CBORItem deviceAuth = val(deviceSigned, "deviceAuth");
        if (deviceAuth instanceof CBORPairList m) deviceAuth = val(m, "deviceSignature");
        if (deviceAuth == null) throw new IllegalStateException("Missing deviceSignature");

        return buildCoseSign1(deviceAuth);
    }

    private PublicKey extractDeviceKey(CBORPairList mso) {
        CBORItem deviceKey = val(map(mso, "deviceKeyInfo"), "deviceKey");
        if (deviceKey == null) throw new IllegalStateException("Missing deviceKeyInfo in MSO");
        try {
            return COSEKey.build(deviceKey).createPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse device key: " + e.getMessage(), e);
        }
    }

    private boolean tryVerifyDevice(
            COSESign1 originalSign1,
            PublicKey deviceKey,
            CBORItemList sessionTranscript,
            String docType,
            CBORItem deviceNameSpaces) {
        try {
            CBORItemList authData = new CBORItemList(
                    new CBORString("DeviceAuthentication"),
                    sessionTranscript,
                    new CBORString(docType),
                    deviceNameSpaces);
            byte[] payload = new CBORTaggedItem(24, new CBORByteArray(authData.encode())).encode();

            COSESign1 withPayload = new COSESign1(
                    originalSign1.getProtectedHeader(),
                    originalSign1.getUnprotectedHeader(),
                    new CBORByteArray(payload),
                    originalSign1.getSignature());
            return new COSEVerifier(deviceKey).verify(withPayload);
        } catch (Exception e) {
            LOG.debugf("Device signature verification attempt failed: %s", e.getMessage());
            return false;
        }
    }

    private void verifyDigests(CBORPairList mso, CBORPairList document) {
        CBORPairList valueDigests = map(mso, "valueDigests");
        CBORPairList nameSpaces = map(map(document, "issuerSigned"), "nameSpaces");
        if (valueDigests == null || nameSpaces == null) return;

        try {
            MessageDigest sha256 = MessageDigest.getInstance(JavaAlgorithm.SHA256);
            for (var nsPair : nameSpaces.getPairs()) {
                String namespace = stringValue(nsPair.getKey());
                if (namespace != null && nsPair.getValue() instanceof CBORItemList elements) {
                    verifyNamespaceDigests(valueDigests, namespace, elements, sha256);
                }
            }
        } catch (Exception e) {
            throw wrapIfNeeded(e, "Digest verification failed: ");
        }
    }

    private void verifyNamespaceDigests(
            CBORPairList valueDigests, String namespace, CBORItemList elements, MessageDigest sha256) {
        CBORPairList nsDigests = map(valueDigests, namespace);
        if (nsDigests == null) {
            return;
        }

        for (CBORItem element : elements.getItems()) {
            verifyElementDigest(element, nsDigests, sha256);
        }
    }

    private void verifyElementDigest(CBORItem element, CBORPairList nsDigests, MessageDigest sha256) {
        CBORPairList item = unwrapTag24(element);
        CBORItem digestIdValue = item != null ? val(item, "digestID") : null;
        if (digestIdValue == null) {
            return;
        }

        int digestId = intValue(digestIdValue);
        if (!(intKeyVal(nsDigests, digestId) instanceof CBORByteArray expected)) {
            throw new IllegalStateException("Missing digest for element " + digestId);
        }
        if (!Arrays.equals(sha256.digest(element.encode()), expected.getValue())) {
            throw new IllegalStateException("Digest mismatch for element " + digestId);
        }
    }

    private void validateValidity(CBORPairList mso) {
        CBORPairList validityInfo = map(mso, "validityInfo");
        if (validityInfo == null) return;
        Instant now = Instant.now();

        Instant validFrom = parseInstant(val(validityInfo, "validFrom"));
        if (validFrom != null && validFrom.isAfter(now)) throw new IllegalStateException("Credential not yet valid");

        Instant validUntil = parseInstant(val(validityInfo, "validUntil"));
        if (validUntil != null && validUntil.isBefore(now)) throw new IllegalStateException("Credential expired");
    }

    private Instant parseInstant(CBORItem value) {
        if (value == null) return null;
        try {
            if (value instanceof CBORTaggedItem tagged) {
                int tag = tagged.getTagNumber().intValue();
                if (tag == 0 || tag == CBOR_TAG_DATE) return Instant.parse(stringValue(tagged.getTagContent()));
            }
            if (value instanceof CBORString s) return Instant.parse(s.getValue());
            if (value instanceof CBORInteger i) return Instant.ofEpochSecond(i.getValue());
            if (value instanceof CBORLong l) return Instant.ofEpochSecond(l.getValue());
        } catch (Exception e) {
            LOG.debugf("Failed to parse validity timestamp: %s", e.getMessage());
        }
        return null;
    }

    private Object cborToJava(CBORItem item) {
        if (item == null) return null;
        return switch (item) {
            case CBORNull ignored -> null;
            case CBORTaggedItem tagged -> {
                int tag = tagged.getTagNumber().intValue();
                yield (tag == 0 || tag == CBOR_TAG_DATE)
                        ? stringValue(tagged.getTagContent())
                        : cborToJava(tagged.getTagContent());
            }
            case CBORString s -> s.getValue();
            case CBORInteger i -> (long) i.getValue();
            case CBORLong l -> l.getValue();
            case CBORBoolean b -> b.getValue();
            case CBORFloat f -> (double) f.getValue();
            case CBORDouble d -> d.getValue();
            case CBORByteArray b -> Base64.getUrlEncoder().withoutPadding().encodeToString(b.getValue());
            case CBORItemList list ->
                list.getItems().stream().map(this::cborToJava).toList();
            case CBORPairList map -> {
                Map<String, Object> result = new LinkedHashMap<>();
                for (var pair : map.getPairs()) {
                    String key = stringValue(pair.getKey());
                    result.put(key != null ? key : pair.getKey().toString(), cborToJava(pair.getValue()));
                }
                yield result;
            }
            default -> item.toString();
        };
    }

    private COSESign1 buildCoseSign1(CBORItem item) {
        try {
            if (item instanceof CBORByteArray bstr) item = decodeCbor(bstr.getValue());
            if (item instanceof CBORTaggedItem tagged && tagged.getTagNumber().intValue() == 18) {
                item = tagged.getTagContent();
            }
            return COSESign1.build(item);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse COSE_Sign1: " + e.getMessage(), e);
        }
    }

    private static CBORItem val(CBORPairList map, String key) {
        if (map == null || map.getPairs() == null) return null;
        for (var pair : map.getPairs()) {
            if (pair.getKey() instanceof CBORString s && s.getValue().equals(key)) return pair.getValue();
        }
        return null;
    }

    private static CBORItem intKeyVal(CBORPairList map, int key) {
        if (map == null || map.getPairs() == null) return null;
        for (var pair : map.getPairs()) {
            CBORItem k = pair.getKey();
            if (k instanceof CBORInteger ci && ci.getValue() == key) return pair.getValue();
            if (k instanceof CBORLong cl && cl.getValue() == key) return pair.getValue();
        }
        return null;
    }

    private static CBORPairList map(CBORPairList parent, String key) {
        return asMap(val(parent, key));
    }

    private static String str(CBORPairList map, String key) {
        return stringValue(val(map, key));
    }

    private static CBORPairList asMap(CBORItem item) {
        return item instanceof CBORPairList m ? m : null;
    }

    private static String stringValue(CBORItem item) {
        return item instanceof CBORString s ? s.getValue() : null;
    }

    private static int intValue(CBORItem item) {
        return switch (item) {
            case CBORInteger i -> i.getValue();
            case CBORLong l -> l.getValue().intValue();
            default -> throw new IllegalStateException("Expected integer, got: " + item);
        };
    }

    private static CBORItem decodeCbor(byte[] bytes) {
        try {
            return new CBORDecoder(bytes).next();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decode CBOR: " + e.getMessage(), e);
        }
    }

    private static IllegalStateException wrapIfNeeded(Exception e, String prefix) {
        if (e instanceof IllegalStateException ise) return ise;
        return new IllegalStateException(prefix + e.getMessage(), e);
    }

    private byte[] decodeBase64(String token) {
        try {
            return Base64.getUrlDecoder().decode(token);
        } catch (Exception e) {
            return Base64.getDecoder().decode(token);
        }
    }
}
