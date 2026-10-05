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
package de.arbeitsagentur.keycloak.oid4vp.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class FailureDetailsTest {

    @Test
    void causeChainJoinsCauseMessages() {
        Exception failure = new IllegalStateException(
                "Unable to verify status list", new IOException("Connection refused", new RuntimeException()));

        assertThat(FailureDetails.causeChain(failure))
                .isEqualTo("Unable to verify status list <- Connection refused <- RuntimeException");
    }

    @Test
    void causeChainSkipsCauseMessagesAlreadyRepeated() {
        IllegalStateException cause = new IllegalStateException("Status list JWT has expired");
        Exception failure = new IllegalStateException("VP token processing failed: " + cause.getMessage(), cause);

        assertThat(FailureDetails.causeChain(failure))
                .isEqualTo("VP token processing failed: Status list JWT has expired");
    }

    @Test
    void singleLineReplacesLineBreakingCharacters() {
        assertThat(FailureDetails.singleLine("state\r\nINFO forged\u2028line\u0085end"))
                .isEqualTo("state  INFO forged line end");
        assertThat(FailureDetails.singleLine(null)).isNull();
    }

    @Test
    void causeChainKeepsForgedLinesOnOneLine() {
        assertThat(FailureDetails.causeChain(new IllegalStateException("bad kid\nWARN forged")))
                .isEqualTo("bad kid WARN forged");
    }

    @Test
    void bodySnippetFlattensAndTruncatesBody() {
        assertThat(FailureDetails.bodySnippet("<html>\n  <body>Bad Gateway</body>\n</html>"))
                .isEqualTo("<html> <body>Bad Gateway</body> </html>");
        assertThat(FailureDetails.bodySnippet("x".repeat(400))).startsWith("x".repeat(300) + "... (400 chars)");
        assertThat(FailureDetails.bodySnippet("  ")).isEqualTo("<empty>");
    }

    @Test
    void relativeToNowStatesDirection() {
        assertThat(FailureDetails.relativeToNow(Instant.now().minusSeconds(90))).endsWith("s ago)");
        assertThat(FailureDetails.relativeToNow(Instant.now().plusSeconds(90))).contains("(in ");
        assertThat(FailureDetails.relativeToNow(null)).isEqualTo("<unset>");
    }
}
