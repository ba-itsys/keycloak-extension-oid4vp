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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_SD_JWT_VC;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CredentialIdTest {

    @Test
    void resolve_validConfiguredId_isUsedVerbatim() {
        assertThat(CredentialId.resolve("pid-credential", FORMAT_SD_JWT_VC, "urn:eudi:pid:1"))
                .isEqualTo("pid-credential");
    }

    @Test
    void resolve_trimsSurroundingWhitespaceOfAValidId() {
        assertThat(CredentialId.resolve("  pid_credential  ", FORMAT_SD_JWT_VC, "urn:eudi:pid:1"))
                .isEqualTo("pid_credential");
    }

    @Test
    void resolve_blankConfiguredId_fallsBackToDerivedId() {
        assertThat(CredentialId.resolve("  ", FORMAT_SD_JWT_VC, "urn:eudi:pid:1"))
                .isEqualTo(CredentialId.defaultFor(FORMAT_SD_JWT_VC, "urn:eudi:pid:1"));
    }

    // The DCQL query and the claim mappers both resolve the id this way, so an id that DCQL cannot carry
    // (a space is not a legal DCQL id character) resolves to the same derived id on both sides. Otherwise
    // the wallet would be asked for the derived id while the mapper looked up the raw id and mapped
    // nothing, silently dropping the claim.
    @Test
    void resolve_invalidConfiguredId_fallsBackToDerivedIdOnBothSides() {
        String derived = CredentialId.defaultFor(FORMAT_SD_JWT_VC, "urn:eudi:pid:1");

        assertThat(CredentialId.isValid("pid credential")).isFalse();
        assertThat(CredentialId.resolve("pid credential", FORMAT_SD_JWT_VC, "urn:eudi:pid:1"))
                .isEqualTo(derived);
    }
}
