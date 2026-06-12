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

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORString;
import org.junit.jupiter.api.Test;

class MdocSessionTranscriptBuilderTest {

    private static final String CLIENT_ID = "https://verifier.example.com";
    private static final String NONCE = "test-nonce-12345";
    private static final String RESPONSE_URI = "https://verifier.example.com/response";
    private static final String MDOC_GENERATED_NONCE = "mdoc-nonce-67890";

    @Test
    void buildOid4vp_producesCorrectStructure() {
        CBORItemList transcript = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        // SessionTranscript = [null, null, OID4VPHandover]
        assertThat(transcript.getItems()).hasSize(3);
        assertThat(transcript.getItems().get(0)).isInstanceOf(CBORNull.class);
        assertThat(transcript.getItems().get(1)).isInstanceOf(CBORNull.class);

        // OID4VPHandover = ["OpenID4VPHandover", SHA-256(...)]
        CBORItemList handover = (CBORItemList) transcript.getItems().get(2);
        assertThat(handover.getItems()).hasSize(2);
        assertThat(handover.getItems().get(0)).isInstanceOf(CBORString.class);
        assertThat(((CBORString) handover.getItems().get(0)).getValue()).isEqualTo("OpenID4VPHandover");
        assertThat(handover.getItems().get(1)).isInstanceOf(CBORByteArray.class);
        assertThat(((CBORByteArray) handover.getItems().get(1)).getValue()).hasSize(32); // SHA-256
    }

    @Test
    void buildOid4vp_withJwkThumbprint_includesInHash() {
        byte[] thumbprint = new byte[] {1, 2, 3, 4, 5};

        CBORItemList withThumbprint =
                MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, thumbprint);
        CBORItemList withoutThumbprint = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        // Different thumbprints should produce different hashes
        CBORItemList handoverWith = (CBORItemList) withThumbprint.getItems().get(2);
        CBORItemList handoverWithout =
                (CBORItemList) withoutThumbprint.getItems().get(2);
        byte[] hashWith = ((CBORByteArray) handoverWith.getItems().get(1)).getValue();
        byte[] hashWithout = ((CBORByteArray) handoverWithout.getItems().get(1)).getValue();
        assertThat(hashWith).isNotEqualTo(hashWithout);
    }

    @Test
    void buildIso18013_7_producesCorrectStructure() {
        CBORItemList transcript =
                MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

        // SessionTranscript = [null, null, [clientIdHash, responseUriHash, nonce]]
        assertThat(transcript.getItems()).hasSize(3);
        assertThat(transcript.getItems().get(0)).isInstanceOf(CBORNull.class);
        assertThat(transcript.getItems().get(1)).isInstanceOf(CBORNull.class);

        CBORItemList handover = (CBORItemList) transcript.getItems().get(2);
        assertThat(handover.getItems()).hasSize(3);
        assertThat(handover.getItems().get(0)).isInstanceOf(CBORByteArray.class);
        assertThat(((CBORByteArray) handover.getItems().get(0)).getValue()).hasSize(32); // SHA-256
        assertThat(handover.getItems().get(1)).isInstanceOf(CBORByteArray.class);
        assertThat(((CBORByteArray) handover.getItems().get(1)).getValue()).hasSize(32); // SHA-256
        assertThat(handover.getItems().get(2)).isInstanceOf(CBORString.class);
        assertThat(((CBORString) handover.getItems().get(2)).getValue()).isEqualTo(NONCE);
    }

    @Test
    void bothFormats_produceDifferentTranscripts() {
        CBORItemList oid4vp = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
        CBORItemList iso =
                MdocSessionTranscriptBuilder.buildIso18013_7(CLIENT_ID, NONCE, RESPONSE_URI, MDOC_GENERATED_NONCE);

        assertThat(oid4vp.encode()).isNotEqualTo(iso.encode());
    }

    @Test
    void buildOid4vp_deterministicOutput() {
        CBORItemList first = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);
        CBORItemList second = MdocSessionTranscriptBuilder.buildOid4vp(CLIENT_ID, NONCE, RESPONSE_URI, null);

        assertThat(first.encode()).isEqualTo(second.encode());
    }
}
