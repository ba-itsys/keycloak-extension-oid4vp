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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class OpenId4VpHandoverInfoTest {

    // The example of OID4VP 1.0 Appendix B.2.6.1.
    @Test
    void buildsTheSessionTranscriptOfTheSpecificationExample() {
        OpenId4VpHandoverInfo handoverInfo = new OpenId4VpHandoverInfo(
                "x509_san_dns:example.com",
                "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                HexFormat.of().parseHex("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"),
                "https://example.com/response");

        assertThat(HexFormat.of().formatHex(handoverInfo.sessionTranscript().encode()))
                .isEqualTo("83f6f6"
                        + "82714f70656e494434565048616e646f7665725820"
                        + "048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac");
    }

    @Test
    void anUnencryptedResponseBindsNoThumbprint() {
        OpenId4VpHandoverInfo unencrypted = new OpenId4VpHandoverInfo("client", "nonce", null, "https://rp/response");
        OpenId4VpHandoverInfo encrypted =
                new OpenId4VpHandoverInfo("client", "nonce", new byte[] {1}, "https://rp/response");

        assertThat(unencrypted.sessionTranscript().encode())
                .isNotEqualTo(encrypted.sessionTranscript().encode());
    }

    @Test
    void requiresTheRequestValues() {
        assertThatThrownBy(() -> new OpenId4VpHandoverInfo("client", null, null, "https://rp/response"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
