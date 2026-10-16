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
package de.arbeitsagentur.keycloak.oid4vp.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpMessages;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderModel;

class Oid4vpPresentationSessionTest {

    static final String ALIAS = "pid";
    private static final String EXECUTION = "pid-check";
    private static final String IDENTITY_KEY = "pid-identity-key";
    private static final String RETURN_URL =
            "http://kc/realms/r/login-actions/required-action?execution=pid-check&client_id=wallet&tab_id=t1";

    private final InMemoryAuthenticationSession authSession = new InMemoryAuthenticationSession();

    @Test
    void keepsTheVerifiedPresentationAndReturnsTheBrowserToTheExecution() {
        waitFor(EXECUTION);

        Response response = Oid4vpPresentationSession.complete(authSession, presentedPid());

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getLocation()).hasToString(RETURN_URL);
        Oid4vpPresentation presentation =
                Oid4vpPresentationSession.result(authSession).orElseThrow();
        assertThat(presentation.identityProviderAlias()).isEqualTo(ALIAS);
        assertThat(presentation.execution()).isEqualTo(EXECUTION);
        assertThat(presentation.credentials().byCredentialId().get("pid").claims())
                .containsEntry("given_name", "ERIKA");
        assertThat(presentation.issuer()).isEqualTo("https://pid-provider.example");
        assertThat(presentation.presentationFlow()).isEqualTo("same_device");
        assertThat(Oid4vpPresentationSession.isPending(authSession, ALIAS)).isFalse();
        assertThat(Oid4vpPresentationSession.failure(authSession, EXECUTION)).isEmpty();
    }

    @Test
    void keepsTheIdentityKeyThatALoginThroughTheIdentityProviderLinks() {
        waitFor(EXECUTION);

        Oid4vpPresentationSession.complete(authSession, presentedPid());

        Oid4vpPresentation presentation =
                Oid4vpPresentationSession.result(authSession).orElseThrow();
        assertThat(presentation.identityKey()).isEqualTo(IDENTITY_KEY);
        assertThat(presentation.subjectCredentialMissing()).isFalse();
    }

    @Test
    void aPresentationWithoutTheSubjectCredentialIdentifiesNobody() {
        waitFor(EXECUTION);
        BrokeredIdentityContext context = presentedPid();
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY, "generated-subject");

        Oid4vpPresentationSession.complete(authSession, context);

        Oid4vpPresentation presentation =
                Oid4vpPresentationSession.result(authSession).orElseThrow();
        assertThat(presentation.identityKey()).isNull();
        assertThat(presentation.subjectCredentialMissing()).isTrue();
    }

    @Test
    void presentationsWithAThrowawaySubjectIdentifyNobody() {
        BrokeredIdentityContext presentationOnly = presentedPid();
        presentationOnly.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_ONLY_KEY, "true");
        BrokeredIdentityContext transientUser = presentedPid();
        transientUser.getIdpConfig().getConfig().put(IdentityProviderModel.DO_NOT_STORE_USERS, "true");

        for (BrokeredIdentityContext context : new BrokeredIdentityContext[] {presentationOnly, transientUser}) {
            waitFor(EXECUTION);
            Oid4vpPresentationSession.complete(authSession, context);

            Oid4vpPresentation presentation =
                    Oid4vpPresentationSession.result(authSession).orElseThrow();
            assertThat(presentation.identityKey()).isNull();
            assertThat(presentation.subjectCredentialMissing()).isFalse();
        }
    }

    @Test
    void reportsAFailureOnlyToTheExecutionThatAskedForThePresentation() {
        waitFor(EXECUTION);

        Response response = Oid4vpPresentationSession.fail(authSession, Oid4vpMessages.PRESENTATION_CANCELLED);

        assertThat(response.getLocation()).hasToString(RETURN_URL);
        assertThat(Oid4vpPresentationSession.failure(authSession, EXECUTION))
                .contains(Oid4vpMessages.PRESENTATION_CANCELLED);
        assertThat(Oid4vpPresentationSession.failure(authSession, "other-execution"))
                .isEmpty();
        assertThat(Oid4vpPresentationSession.result(authSession)).isEmpty();
    }

    @Test
    void waitsOnlyForTheIdentityProviderThatWasAsked() {
        waitFor(EXECUTION);

        assertThat(Oid4vpPresentationSession.isPending(authSession, ALIAS)).isTrue();
        assertThat(Oid4vpPresentationSession.isPending(authSession, "wallet-login"))
                .isFalse();
        assertThat(Oid4vpPresentationSession.isPending(null, ALIAS)).isFalse();
    }

    @Test
    void clearForgetsThePresentation() {
        waitFor(EXECUTION);
        Oid4vpPresentationSession.complete(authSession, presentedPid());

        Oid4vpPresentationSession.clear(authSession);

        assertThat(authSession.authNotes).isEmpty();
    }

    @Test
    void discardsAnUnreadablePresentation() {
        authSession.setAuthNote(Oid4vpPresentationSession.RESULT_NOTE, "{not json");

        assertThat(Oid4vpPresentationSession.result(authSession)).isEmpty();
        assertThat(authSession.authNotes).doesNotContainKey(Oid4vpPresentationSession.RESULT_NOTE);
    }

    private void waitFor(String execution) {
        authSession.setAuthNote(Oid4vpPresentationSession.ALIAS_NOTE, ALIAS);
        authSession.setAuthNote(Oid4vpPresentationSession.EXECUTION_NOTE, execution);
        authSession.setAuthNote(Oid4vpPresentationSession.RETURN_URL_NOTE, RETURN_URL);
    }

    static BrokeredIdentityContext presentedPid() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(ALIAS);
        model.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext(IDENTITY_KEY, model);
        context.getContextData()
                .put(
                        Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY,
                        new PresentedCredentials(Map.of(
                                "pid",
                                new PresentedCredential(
                                        "dc+sd-jwt", "urn:eudi:pid:de:1", Map.of("given_name", "ERIKA")))));
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY, "https://pid-provider.example");
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY, "same_device");
        return context;
    }
}
