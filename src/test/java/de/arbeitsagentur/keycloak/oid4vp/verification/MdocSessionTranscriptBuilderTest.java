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

import static org.assertj.core.api.Assertions.*;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.junit.jupiter.api.Test;

class MdocSessionTranscriptBuilderTest {

    private static final String CLIENT_ID = "https://verifier.example.com";
    private static final String NONCE = "test-nonce-12345";
    private static final String RESPONSE_URI = "https://verifier.example.com/response";
    private static final String MDOC_GENERATED_NONCE = "mdoc-nonce-67890";

    @Test
    void buildOid4vp_producesCorrectStructure() {
        CBORObject transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        // SessionTranscript = [null, null, OID4VPHandover]
        assertThat(transcript.getType()).isEqualTo(CBORType.Array);
        assertThat(transcript.size()).isEqualTo(3);
        assertThat(transcript.get(0).isNull()).isTrue();
        assertThat(transcript.get(1).isNull()).isTrue();

        // OID4VPHandover = ["OpenID4VPHandover", SHA-256(...)]
        CBORObject handover = transcript.get(2);
        assertThat(handover.getType()).isEqualTo(CBORType.Array);
        assertThat(handover.size()).isEqualTo(2);
        assertThat(handover.get(0).AsString()).isEqualTo("OpenID4VPHandover");
        assertThat(handover.get(1).getType()).isEqualTo(CBORType.ByteString);
        assertThat(handover.get(1).GetByteString()).hasSize(32); // SHA-256 output
    }

    @Test
    void buildOid4vp_withJwkThumbprint_includesInHash() {
        byte[] thumbprint = new byte[] {1, 2, 3, 4, 5};

        CBORObject withThumbprint =
                MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, thumbprint);
        CBORObject withoutThumbprint = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        // Different thumbprints should produce different hashes
        byte[] hashWith = withThumbprint.get(2).get(1).GetByteString();
        byte[] hashWithout = withoutThumbprint.get(2).get(1).GetByteString();
        assertThat(hashWith).isNotEqualTo(hashWithout);
    }

    @Test
    void buildIso18013_7_producesCorrectStructure() {
        CBORObject transcript =
                MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

        // SessionTranscript = [null, null, [clientIdHash, responseUriHash, nonce]]
        assertThat(transcript.getType()).isEqualTo(CBORType.Array);
        assertThat(transcript.size()).isEqualTo(3);
        assertThat(transcript.get(0).isNull()).isTrue();
        assertThat(transcript.get(1).isNull()).isTrue();

        CBORObject handover = transcript.get(2);
        assertThat(handover.getType()).isEqualTo(CBORType.Array);
        assertThat(handover.size()).isEqualTo(3);
        assertThat(handover.get(0).getType()).isEqualTo(CBORType.ByteString);
        assertThat(handover.get(0).GetByteString()).hasSize(32); // SHA-256
        assertThat(handover.get(1).getType()).isEqualTo(CBORType.ByteString);
        assertThat(handover.get(1).GetByteString()).hasSize(32); // SHA-256
        assertThat(handover.get(2).AsString()).isEqualTo(NONCE);
    }

    @Test
    void bothFormats_produceDifferentTranscripts() {
        CBORObject oid4vp = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
        CBORObject iso =
                MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

        assertThat(oid4vp.EncodeToBytes()).isNotEqualTo(iso.EncodeToBytes());
    }

    @Test
    void buildOid4vp_deterministicOutput() {
        CBORObject first = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
        CBORObject second = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        assertThat(first.EncodeToBytes()).isEqualTo(second.EncodeToBytes());
    }
}
