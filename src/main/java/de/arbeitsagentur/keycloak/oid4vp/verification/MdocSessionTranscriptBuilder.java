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

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORString;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.keycloak.crypto.JavaAlgorithm;

/**
 * Builds mDoc SessionTranscript structures for device authentication verification.
 *
 * <p>Supports two competing handover formats that wallets may use:
 *
 * <h3>OpenID4VP 1.0 (Appendix B.3.2.2)</h3>
 * <pre>
 * SessionTranscript = [
 *   null,                     // DeviceEngagementBytes (not used in OID4VP)
 *   null,                     // EReaderKeyBytes (not used in OID4VP)
 *   OID4VPHandover
 * ]
 * OID4VPHandover = [
 *   "OpenID4VPHandover",
 *   SHA-256(CBOR([client_id, nonce, jwk_thumbprint_or_null, response_uri]))
 * ]
 * </pre>
 *
 * <h3>ISO 18013-7 Annex B.4.4</h3>
 * Used by wallets that include an {@code mdoc_generated_nonce} in the JWE {@code apu} header.
 * <pre>
 * SessionTranscript = [
 *   null,
 *   null,
 *   [
 *     SHA-256(CBOR([client_id, mdoc_generated_nonce])),
 *     SHA-256(CBOR([response_uri, mdoc_generated_nonce])),
 *     nonce
 *   ]
 * ]
 * </pre>
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.2.2">OID4VP 1.0 Appendix B.3.2.2</a>
 * @see <a href="https://www.iso.org/standard/82772.html">ISO/IEC 18013-7 Annex B.4.4</a>
 */
final class MdocSessionTranscriptBuilder {

    private static final String HANDOVER_TYPE = "OpenID4VPHandover";
    private static final String HASH_ALGORITHM = JavaAlgorithm.SHA256;

    private MdocSessionTranscriptBuilder() {}

    /**
     * Builds the OID4VP 1.0 SessionTranscript (Appendix B.3.2.2).
     *
     * @param clientId the verifier's client_id
     * @param nonce the authorization request nonce
     * @param responseUri the response_uri from the request
     * @param jwkThumbprint optional JWK thumbprint (may be null)
     */
    static CBORItemList buildOid4vp(String clientId, String nonce, String responseUri, byte[] jwkThumbprint) {
        CBORItemList info = new CBORItemList(
                new CBORString(clientId),
                new CBORString(nonce),
                jwkThumbprint != null && jwkThumbprint.length > 0
                        ? new CBORByteArray(jwkThumbprint)
                        : CBORNull.INSTANCE,
                new CBORString(responseUri));
        byte[] hash = sha256(info.encode());

        CBORItemList handover = new CBORItemList(new CBORString(HANDOVER_TYPE), new CBORByteArray(hash));

        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }

    /**
     * Builds the ISO 18013-7 Annex B.4.4 SessionTranscript.
     *
     * @param clientId the verifier's client_id
     * @param nonce the authorization request nonce
     * @param responseUri the response_uri from the request
     * @param mdocGeneratedNonce the nonce from the JWE {@code apu} header
     */
    static CBORItemList buildIso18013_7(String clientId, String nonce, String responseUri, String mdocGeneratedNonce) {
        byte[] clientIdHash =
                sha256(new CBORItemList(new CBORString(clientId), new CBORString(mdocGeneratedNonce)).encode());

        byte[] responseUriHash =
                sha256(new CBORItemList(new CBORString(responseUri), new CBORString(mdocGeneratedNonce)).encode());

        CBORItemList handover = new CBORItemList(
                new CBORByteArray(clientIdHash), new CBORByteArray(responseUriHash), new CBORString(nonce));

        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
