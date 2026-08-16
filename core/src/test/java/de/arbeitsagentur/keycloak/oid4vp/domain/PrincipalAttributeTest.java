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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class PrincipalAttributeTest {

    @Test
    void readsTheEntriesInTheConfiguredOrder() {
        assertThat(PrincipalAttribute.parse("pid_sd_jwt:sub, pid_mdoc:sub"))
                .as("the first one a wallet presents supplies the subject, so the order is the configuration")
                .containsExactly(
                        new PrincipalAttribute("pid_sd_jwt", "sub"), new PrincipalAttribute("pid_mdoc", "sub"));
    }

    @Test
    void everyCredentialCarriesItsOwnClaim() {
        // An SD-JWT credential carries the subject as a claim of its own, an mDoc as a data element
        // of a namespace, and a credential this Keycloak issues wherever its mapper wrote it.
        assertThat(PrincipalAttribute.parse("pid:personal_administrative_number, employee:sub"))
                .containsExactly(
                        new PrincipalAttribute("pid", "personal_administrative_number"),
                        new PrincipalAttribute("employee", "sub"));
    }

    @Test
    void readsANestedClaimPath() {
        assertThat(PrincipalAttribute.parse("employee:credential_subject.id"))
                .containsExactly(new PrincipalAttribute("employee", "credential_subject.id"));
    }

    @Test
    void anMdocPathNamesItsNamespaceBeforeTheElement() {
        // DCQL asks for the namespace and the element separately, and the presentation nests the
        // element inside the namespace, so both halves are read off the one configured path.
        PrincipalAttribute mdocPid = PrincipalAttribute.parse("pid_mdoc:eu\\.europa\\.ec\\.eudi\\.pid\\.1.family_name")
                .get(0);

        assertThat(mdocPid.mdocNamespace())
                .as("the dots of the namespace are escaped, so they do not separate steps")
                .isEqualTo("eu.europa.ec.eudi.pid.1");
        assertThat(mdocPid.mdocElementPath()).isEqualTo("family_name");
    }

    @Test
    void aPathOfOneStepNamesNoMdocNamespace() {
        PrincipalAttribute employee = PrincipalAttribute.parse("employee:sub").get(0);

        assertThat(employee.mdocNamespace())
                .as("an SD-JWT credential presents its claims without a namespace")
                .isNull();
        assertThat(employee.mdocElementPath()).isEqualTo("sub");
    }

    @Test
    void anEmptyConfigurationNamesNoCredential() {
        assertThat(PrincipalAttribute.parse(null)).isEmpty();
        assertThat(PrincipalAttribute.parse("   ")).isEmpty();
    }

    @Test
    void anEntryWithoutAClaimIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("employee"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("names no claim");
    }

    @Test
    void anEntryWithAnEmptyHalfIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("employee:"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("needs both");
        assertThatThrownBy(() -> PrincipalAttribute.parse(":sub"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("needs both");
    }

    @Test
    void aCredentialTypePastedInsteadOfItsIdIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("urn:eudi:pid:1:sub"))
                .as("the credential id is the DCQL id of a mapper, not the credential type")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("more than one ':'");
    }

    @Test
    void aCredentialIdThatIsNotADcqlIdIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("pid credential:sub"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("valid DCQL id");
    }

    @Test
    void aMalformedClaimPathIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("employee:sub."))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("valid claim path");
    }

    @Test
    void namingACredentialTwiceIsRejected() {
        assertThatThrownBy(() -> PrincipalAttribute.parse("employee:sub, employee:other"))
                .as("it would be unclear which of the two claims carries the subject")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("more than once");
    }

    @Test
    void listsTheCredentialIdsInOrder() {
        assertThat(PrincipalAttribute.credentialIdsOf(PrincipalAttribute.parse("pid_sd_jwt:sub, pid_mdoc:sub")))
                .isEqualTo(List.of("pid_sd_jwt", "pid_mdoc"));
    }
}
