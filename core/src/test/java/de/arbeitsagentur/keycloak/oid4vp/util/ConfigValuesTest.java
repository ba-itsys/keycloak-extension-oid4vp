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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class ConfigValuesTest {

    private static final String PEM = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";

    @Test
    void pem_decodesBase64EncodedBundle() {
        String encoded = Base64.getEncoder().encodeToString(PEM.getBytes(StandardCharsets.UTF_8));
        assertThat(ConfigValues.pem(encoded)).isEqualTo(PEM);
    }

    @Test
    void pem_decodesLineWrappedBase64() {
        String longPem = PEM + "\n" + PEM;
        String encoded = Base64.getMimeEncoder().encodeToString(longPem.getBytes(StandardCharsets.UTF_8));
        assertThat(encoded).contains("\r\n");
        assertThat(ConfigValues.pem(encoded)).isEqualTo(longPem);
    }

    @Test
    void pem_unescapesLineBreaksInPlainValue() {
        assertThat(ConfigValues.pem("-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----"))
                .isEqualTo(PEM);
    }

    @Test
    void pem_unescapesLineBreaksAfterBase64Decoding() {
        String escaped = "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----";
        String encoded = Base64.getEncoder().encodeToString(escaped.getBytes(StandardCharsets.UTF_8));
        assertThat(ConfigValues.pem(encoded)).isEqualTo(PEM);
    }

    @Test
    void pem_keepsVerbatimPemThatIsAlsoDecodable() {
        // A PEM body is itself Base64 and would decode without the marker check.
        assertThat(ConfigValues.pem(PEM)).isEqualTo(PEM);
    }

    @Test
    void pem_keepsValueThatDecodesToNonPemContent() {
        String encoded = Base64.getEncoder().encodeToString("not a pem".getBytes(StandardCharsets.UTF_8));
        assertThat(ConfigValues.pem(encoded)).isEqualTo(encoded);
    }

    @Test
    void pem_keepsBlankAndNullValues() {
        assertThat(ConfigValues.pem(null)).isNull();
        assertThat(ConfigValues.pem("")).isEmpty();
    }

    @Test
    void json_decodesBase64EncodedObjectAndArray() {
        String object = "{\"kty\":\"EC\"}";
        String array = "[{\"format\":\"jwt\"}]";
        assertThat(ConfigValues.json(base64(object))).isEqualTo(object);
        assertThat(ConfigValues.json(base64(array))).isEqualTo(array);
    }

    @Test
    void json_keepsPlainJson() {
        String json = "  {\"kty\":\"EC\"}";
        assertThat(ConfigValues.json(json)).isEqualTo(json);
    }

    @Test
    void json_keepsValueThatDecodesToNonJsonContent() {
        String encoded = base64("plain text");
        assertThat(ConfigValues.json(encoded)).isEqualTo(encoded);
    }

    @Test
    void json_keepsBlankAndNullValues() {
        assertThat(ConfigValues.json(null)).isNull();
        assertThat(ConfigValues.json(" ")).isEqualTo(" ");
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
