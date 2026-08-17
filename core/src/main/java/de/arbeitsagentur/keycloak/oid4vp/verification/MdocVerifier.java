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
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import java.io.IOException;
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
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Verifies mDoc (ISO 18013-5) credentials presented in a VP token.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdocVerifier {

    private static final Logger LOG = Logger.getLogger(MdocVerifier.class);
    private static final int CBOR_TAG_DATE = 1004;

    private final int clockSkewSeconds;

    /**
     * @param clockSkewSeconds tolerance applied to the validity window of the MSO, so a credential
     *     is not rejected over a clock difference between issuer and verifier
     */
    public MdocVerifier(int clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

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

    /**
     * Verifies only the issuer signature (and its value digests when the MSO carries them) of an mDoc.
     *
     * <p>This is not a wallet-presentation check: it performs no device authentication and does not bind
     * the credential to a session, so it must not be used to accept a presented credential. Use
     * {@link #verifyPresentation} for that.
     */
    MdocVerificationResult verifyIssuerSigned(String deviceResponseToken, ResolvedTrust trust) {
        return verify(deviceResponseToken, trust, null);
    }

    /**
     * Fully verifies an mDoc presented in a VP token: issuer signature, MSO validity window, value
     * digests, and device authentication that binds the presentation to this session.
     *
     * <p>Device authentication and value-digest verification are mandatory here (ISO/IEC 18013-5, 9.1.2):
     * a {@code DeviceResponse} that omits {@code deviceSigned}, omits the Mobile Security Object, or whose
     * issuer-signed values are not digest-covered is rejected rather than silently accepted. The OID4VP 1.0
     * session transcript is tried first, with the ISO/IEC 18013-7 transcript as a fallback when
     * {@code mdocGeneratedNonce} is present.
     *
     * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021, 9.1.2 (mdoc authentication)</a>
     */
    public MdocVerificationResult verifyPresentation(
            String deviceResponseToken,
            ResolvedTrust trust,
            String clientId,
            String nonce,
            String responseUri,
            String mdocGeneratedNonce,
            byte[] jwkThumbprint) {
        if (clientId == null || nonce == null || responseUri == null) {
            throw new IllegalStateException(
                    "mDoc presentation verification requires client_id, nonce and response_uri");
        }
        return verify(
                deviceResponseToken,
                trust,
                new DeviceAuthContext(clientId, nonce, responseUri, mdocGeneratedNonce, jwkThumbprint));
    }

    /** Session-binding inputs for device authentication; {@code null} selects issuer-signature-only mode. */
    private record DeviceAuthContext(
            String clientId, String nonce, String responseUri, String mdocGeneratedNonce, byte[] jwkThumbprint) {}

    private MdocVerificationResult verify(
            String deviceResponseToken, ResolvedTrust trust, DeviceAuthContext deviceAuth) {
        try {
            CBORPairList document = parseDocument(decodeBase64(deviceResponseToken));

            CBORPairList issuerSigned = map(document, "issuerSigned");
            if (issuerSigned == null) {
                throw new IllegalStateException("mDoc document carries no issuerSigned structure");
            }
            CBORPairList mso = parseMso(document);
            if (mso == null) {
                throw new IllegalStateException("mDoc issuerAuth carries no Mobile Security Object");
            }

            String docType = resolveDocType(document, mso);

            verifyIssuerSignature(document, trust);
            // Claims and digests are both read from the issuer-signed namespaces, so a document can never
            // present one set of values while a different set is digest-checked.
            verifyDigests(mso, issuerSigned, deviceAuth != null);
            validateValidity(mso, deviceAuth != null);
            Map<String, Object> claims = extractClaims(issuerSigned, mso);

            if (deviceAuth != null) {
                verifyDeviceAuth(
                        document,
                        mso,
                        docType,
                        deviceAuth.clientId(),
                        deviceAuth.nonce(),
                        deviceAuth.responseUri(),
                        deviceAuth.mdocGeneratedNonce(),
                        deviceAuth.jwkThumbprint());
            }

            return new MdocVerificationResult(claims, docType);
        } catch (Exception e) {
            throw wrapIfNeeded(e, "mDoc verification failed: ");
        }
    }

    /**
     * The document-level docType must equal the issuer-signed MSO docType (ISO/IEC 18013-5, 9.1.2);
     * the MSO value wins because only it is covered by the issuer signature.
     */
    private String resolveDocType(CBORPairList document, CBORPairList mso) {
        String documentDocType = str(document, "docType");
        String msoDocType = str(mso, "docType");
        if (documentDocType != null && msoDocType != null && !documentDocType.equals(msoDocType)) {
            throw new IllegalStateException("mDoc docType '" + documentDocType
                    + "' does not match the Mobile Security Object docType '" + msoDocType + "'");
        }
        if (msoDocType != null) return msoDocType;
        if (documentDocType != null) return documentDocType;
        return "mso_mdoc";
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

    private Map<String, Object> extractClaims(CBORPairList issuerSigned, CBORPairList mso) {
        Map<String, Object> claims = new LinkedHashMap<>();

        CBORPairList nameSpaces = map(issuerSigned, "nameSpaces");
        if (nameSpaces != null) {
            for (var nsPair : nameSpaces.getPairs()) {
                String namespace = stringValue(nsPair.getKey());
                if (namespace != null && nsPair.getValue() instanceof CBORItemList elementsList) {
                    addNamespaceClaims(claims, namespace, elementsList);
                }
            }
        }

        CBORItem status = val(mso, "status");
        if (status != null) claims.put("status", cborToJava(status));
        return claims;
    }

    private void addNamespaceClaims(Map<String, Object> claims, String namespace, CBORItemList elementsList) {
        Map<String, Object> namespaceClaims = new LinkedHashMap<>();
        for (CBORItem element : elementsList.getItems()) {
            CBORPairList item = unwrapTag24(element);
            if (item != null) {
                String elementId = str(item, "elementIdentifier");
                if (elementId != null) {
                    namespaceClaims.put(elementId, structuredValue(cborToJava(val(item, "elementValue"))));
                }
            }
        }
        claims.put(namespace, namespaceClaims);
    }

    // A JSON object or array serialized into a string element becomes a nested structure in the
    // claims JSON, so mDoc claims follow the same addressing rules as SD-JWT claims.
    private Object structuredValue(Object value) {
        if (!(value instanceof String text)) {
            return value;
        }
        String stripped = text.stripLeading();
        if (!stripped.startsWith("{") && !stripped.startsWith("[")) {
            return value;
        }
        try {
            Object parsed = JsonSerialization.readValue(text, Object.class);
            return parsed instanceof Map || parsed instanceof List ? parsed : value;
        } catch (IOException e) {
            return value;
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

    private void verifyIssuerSignature(CBORPairList document, ResolvedTrust trust) {
        if (trust == null || !trust.hasIssuerTrust()) {
            throw new IllegalStateException("No trusted keys available for mDoc signature verification");
        }

        CBORItem issuerAuth = val(map(document, "issuerSigned"), "issuerAuth");
        if (issuerAuth == null) throw new IllegalStateException("No issuerAuth found");

        try {
            COSESign1 sign1 = buildCoseSign1(issuerAuth);

            List<X509Certificate> x5chain = extractX5Chain(sign1);
            if (x5chain != null && !x5chain.isEmpty()) {
                PublicKey leafKey = trust.validateIssuerChain(x5chain);
                if (leafKey != null && new COSEVerifier(leafKey).verify(sign1)) return;
            }

            // An mDoc names no issuer, so every pinned certificate is tried; the doctype the trust
            // material is scoped to is what keeps the trust domains apart here.
            for (X509Certificate cert : trust.pinnedCertificates()) {
                try {
                    cert.checkValidity();
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

        CBORItemList oid4vpTranscript =
                MdocSessionTranscriptBuilder.buildOid4vp(clientId, nonce, responseUri, jwkThumbprint);
        if (tryVerifyDevice(deviceSign1, deviceKey, oid4vpTranscript, docType, deviceNameSpaces)) {
            LOG.debug("Device auth verified using OID4VP 1.0 transcript");
            return;
        }

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

    private void verifyDigests(CBORPairList mso, CBORPairList issuerSigned, boolean mandatory) {
        CBORPairList valueDigests = map(mso, "valueDigests");
        CBORPairList nameSpaces = map(issuerSigned, "nameSpaces");
        if (valueDigests == null || nameSpaces == null) {
            if (mandatory) {
                throw new IllegalStateException(
                        "mDoc presentation is missing the value digests that authenticate its claims");
            }
            return;
        }

        String digestAlgorithm = digestAlgorithm(mso);
        try {
            for (var nsPair : nameSpaces.getPairs()) {
                String namespace = stringValue(nsPair.getKey());
                if (namespace != null && nsPair.getValue() instanceof CBORItemList elements) {
                    verifyNamespaceDigests(valueDigests, namespace, elements, digestAlgorithm);
                }
            }
        } catch (Exception e) {
            throw wrapIfNeeded(e, "Digest verification failed: ");
        }
    }

    /**
     * The algorithm the value digests are computed with, which the Mobile Security Object declares
     * and the issuer signature covers. ISO/IEC 18013-5 defines SHA-256, SHA-384 and SHA-512 for it;
     * a document that declares none is read as SHA-256, and one that declares anything else is
     * rejected rather than judged by an algorithm its issuer did not use.
     */
    private String digestAlgorithm(CBORPairList mso) {
        String declared = str(mso, "digestAlgorithm");
        if (declared == null) {
            return JavaAlgorithm.SHA256;
        }
        return switch (declared) {
            case JavaAlgorithm.SHA256, JavaAlgorithm.SHA384, JavaAlgorithm.SHA512 -> declared;
            default -> throw new IllegalStateException("Unsupported mDoc digest algorithm: " + declared);
        };
    }

    private void verifyNamespaceDigests(
            CBORPairList valueDigests, String namespace, CBORItemList elements, String digestAlgorithm) {
        CBORPairList nsDigests = map(valueDigests, namespace);
        if (nsDigests == null) {
            throw new IllegalStateException("mDoc namespace " + namespace + " has no value digests in the MSO");
        }

        for (CBORItem element : elements.getItems()) {
            verifyElementDigest(element, nsDigests, digestAlgorithm);
        }
    }

    private void verifyElementDigest(CBORItem element, CBORPairList nsDigests, String digestAlgorithm) {
        CBORPairList item = unwrapTag24(element);
        CBORItem digestIdValue = item != null ? val(item, "digestID") : null;
        if (digestIdValue == null) {
            throw new IllegalStateException("mDoc issuer-signed item is missing its digestID");
        }

        int digestId = intValue(digestIdValue);
        if (!(intKeyVal(nsDigests, digestId) instanceof CBORByteArray expected)) {
            throw new IllegalStateException("Missing digest for element " + digestId);
        }
        if (!Arrays.equals(HashUtils.hash(digestAlgorithm, element.encode()), expected.getValue())) {
            throw new IllegalStateException("Digest mismatch for element " + digestId);
        }
    }

    /**
     * Enforces the validity window the issuer signed. A presentation carries it: the MSO of an mDoc
     * holds {@code validityInfo}, so a presentation without it states no validity at all and is
     * rejected rather than accepted as valid forever. ISO/IEC 18013-5 makes {@code validFrom} and
     * {@code validUntil} mandatory in {@code ValidityInfo}, so a validity information that omits a
     * timestamp or carries an unreadable one is rejected as well; the readable window is judged
     * within the configured clock skew.
     */
    private void validateValidity(CBORPairList mso, boolean mandatory) {
        CBORPairList validityInfo = map(mso, "validityInfo");
        if (validityInfo == null) {
            if (mandatory) {
                throw new IllegalStateException("mDoc presentation is missing the validity information of its MSO");
            }
            return;
        }
        Instant now = Instant.now();

        Instant validFrom = requireInstant(validityInfo, "validFrom");
        if (validFrom.isAfter(now.plusSeconds(clockSkewSeconds))) {
            throw new IllegalStateException("Credential not yet valid");
        }

        Instant validUntil = requireInstant(validityInfo, "validUntil");
        if (validUntil.isBefore(now.minusSeconds(clockSkewSeconds))) {
            throw new IllegalStateException("Credential expired");
        }
    }

    /** The named mandatory ValidityInfo timestamp; missing or unreadable ones fail verification. */
    private Instant requireInstant(CBORPairList validityInfo, String field) {
        CBORItem value = val(validityInfo, field);
        if (value == null) {
            throw new IllegalStateException("mDoc validity information is missing its " + field + " timestamp");
        }
        Instant instant = parseInstant(value);
        if (instant == null) {
            throw new IllegalStateException("mDoc validity information carries an unreadable " + field + " timestamp");
        }
        return instant;
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
