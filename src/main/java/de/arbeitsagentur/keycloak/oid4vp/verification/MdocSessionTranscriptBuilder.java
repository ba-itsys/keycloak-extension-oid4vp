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

import com.upokecenter.cbor.CBORObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
    private static final String HASH_ALGORITHM = "SHA-256";

    private MdocSessionTranscriptBuilder() {}

    /**
     * Builds the OID4VP 1.0 SessionTranscript (Appendix B.3.2.2).
     *
     * @param clientId the verifier's client_id
     * @param nonce the authorization request nonce
     * @param responseUri the response_uri from the request
     * @param jwkThumbprint optional JWK thumbprint (may be null)
     */
    static CBORObject buildOid4vp(String clientId, String nonce, String responseUri, byte[] jwkThumbprint) {
        CBORObject info = CBORObject.NewArray();
        info.Add(clientId);
        info.Add(nonce);
        if (jwkThumbprint != null && jwkThumbprint.length > 0) {
            info.Add(jwkThumbprint);
        } else {
            info.Add(CBORObject.Null);
        }
        info.Add(responseUri);
        byte[] hash = sha256(info.EncodeToBytes());

        CBORObject handover = CBORObject.NewArray();
        handover.Add(HANDOVER_TYPE);
        handover.Add(hash);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(handover);
        return sessionTranscript;
    }

    /**
     * Builds the ISO 18013-7 Annex B.4.4 SessionTranscript.
     *
     * @param clientId the verifier's client_id
     * @param nonce the authorization request nonce
     * @param responseUri the response_uri from the request
     * @param mdocGeneratedNonce the nonce from the JWE {@code apu} header
     */
    static CBORObject buildIso18013_7(String clientId, String nonce, String responseUri, String mdocGeneratedNonce) {
        // SHA-256(CBOR([clientId, mdocGeneratedNonce]))
        CBORObject clientIdArray = CBORObject.NewArray();
        clientIdArray.Add(clientId);
        clientIdArray.Add(mdocGeneratedNonce);
        byte[] clientIdHash = sha256(clientIdArray.EncodeToBytes());

        // SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
        CBORObject responseUriArray = CBORObject.NewArray();
        responseUriArray.Add(responseUri);
        responseUriArray.Add(mdocGeneratedNonce);
        byte[] responseUriHash = sha256(responseUriArray.EncodeToBytes());

        CBORObject handover = CBORObject.NewArray();
        handover.Add(clientIdHash);
        handover.Add(responseUriHash);
        handover.Add(nonce);

        CBORObject sessionTranscript = CBORObject.NewArray();
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(CBORObject.Null);
        sessionTranscript.Add(handover);
        return sessionTranscript;
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
