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
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

/**
 * Binds an mDoc presentation to the request it answers. The device signs a SessionTranscript built
 * from these values, so a presentation captured for another verifier or request fails device
 * authentication here.
 *
 * @param jwkThumbprint the RFC 7638 thumbprint of the response encryption key, or null when the
 *     response is not encrypted
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1">OID4VP 1.0 Appendix B.2.6.1</a>
 */
public record OpenId4VpHandoverInfo(String clientId, String nonce, byte[] jwkThumbprint, String responseUri) {

    private static final String HANDOVER_TYPE = "OpenID4VPHandover";

    public OpenId4VpHandoverInfo {
        if (clientId == null || nonce == null || responseUri == null) {
            throw new IllegalArgumentException("mDoc device authentication requires client_id, nonce and response_uri");
        }
    }

    // SessionTranscript = [null, null, ["OpenID4VPHandover", SHA-256(CBOR(OpenID4VPHandoverInfo))]]
    CBORItemList sessionTranscript() {
        CBORItemList handoverInfo = new CBORItemList(
                new CBORString(clientId),
                new CBORString(nonce),
                jwkThumbprint != null && jwkThumbprint.length > 0
                        ? new CBORByteArray(jwkThumbprint)
                        : CBORNull.INSTANCE,
                new CBORString(responseUri));
        CBORItemList handover = new CBORItemList(
                new CBORString(HANDOVER_TYPE),
                new CBORByteArray(HashUtils.hash(JavaAlgorithm.SHA256, handoverInfo.encode())));
        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }
}
