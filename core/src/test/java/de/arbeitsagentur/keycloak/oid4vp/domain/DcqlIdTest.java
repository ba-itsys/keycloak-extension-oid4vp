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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DcqlIdTest {

    @Test
    void isValid_acceptsLettersDigitsUnderscoreAndHyphenOnly() {
        assertThat(DcqlId.isValid("birth-name_1")).isTrue();
        assertThat(DcqlId.isValid("birth name")).isFalse();
        assertThat(DcqlId.isValid("")).isFalse();
        assertThat(DcqlId.isValid(null)).isFalse();
    }

    @Test
    void slug_replacesEveryOtherCharacterByAnUnderscore() {
        assertThat(DcqlId.slug("PID: birth name")).isEqualTo("PID__birth_name");
        assertThat(DcqlId.slug("names.birth[0]")).isEqualTo("names_birth_0_");
        assertThat(DcqlId.slug("birth-name")).isEqualTo("birth-name");
        assertThat(DcqlId.slug(null)).isEmpty();
    }
}
