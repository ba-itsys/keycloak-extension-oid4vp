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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FLOW_CROSS_DEVICE;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FLOW_SAME_DEVICE;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_MSO_MDOC;
import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_SD_JWT_VC;
import static org.assertj.core.api.Assertions.*;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceBindingCheck;
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential.RequestedClaim;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenVerifier;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.crypto.CryptoIntegration;

/**
 * Covers subject resolution, allow-list enforcement, and requested-claims validation with a real
 * configuration and canned verification results. The verification pipeline itself is covered by
 * its own tests and the end-to-end suite.
 */
class Oid4vpCallbackProcessorTest {

    private Oid4vpIdentityProviderConfig config;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(Oid4vpCallbackProcessorTest.class.getClassLoader());
    }

    @BeforeEach
    void setUp() {
        config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        config.setPrincipalAttributes("cred-1:sub");
    }

    @Test
    void process_validSdJwt_returnsBrokeredIdentityContext() {
        VerifiedCredential credential = sdJwtCredential(Map.of("sub", "user1"));

        BrokeredIdentityContext result =
                processor(resultOf(credential)).process(requestContext("test-state", "test-nonce"), "vp-token", null);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("user1");
        PresentedCredential presented =
                Oid4vpMapperUtils.presentedCredentials(result).get("cred-1");
        assertThat(presented.claims()).containsEntry("sub", "user1");
        assertThat(presented.type()).isEqualTo("IdentityCredential");
        assertThat(presented.format()).isEqualTo(FORMAT_SD_JWT_VC);
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY))
                .isEqualTo("https://issuer.example");
    }

    @Test
    void process_recordsTheSameDevicePresentationFlowForMappers() {
        VerifiedCredential credential = sdJwtCredential(Map.of("sub", "user1"));

        BrokeredIdentityContext result =
                processor(resultOf(credential)).process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY))
                .isEqualTo("same_device");
    }

    @Test
    void process_recordsTheCrossDevicePresentationFlow() {
        VerifiedCredential credential = sdJwtCredential(Map.of("sub", "user1"));
        Oid4vpRequestObjectStore.RequestContextEntry crossDeviceContext =
                requestContext("state", "nonce", FLOW_CROSS_DEVICE, null, List.of());

        BrokeredIdentityContext result = processor(resultOf(credential)).process(crossDeviceContext, "vp-token", null);

        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY))
                .isEqualTo("cross_device");
    }

    @Test
    void process_missingRequestContext_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(null, "token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing request context");
    }

    @Test
    void process_missingVpToken_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing vp_token");
    }

    @Test
    void process_missingNonceInRequestContext_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(requestContext("state", null), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("missing the client_id or nonce");
    }

    @Test
    void process_issuerNotAllowed_throws() {
        config.setAllowedIssuers("https://trusted-issuer.example");
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Issuer not allowed");
    }

    // The allow-list must reject a disallowed issuer wherever it appears, not only on the first
    // credential. In a multi-credential response the claims of every presented credential reach
    // the mappers.
    @Test
    void process_multiCredentialWithDisallowedSecondIssuer_throws() {
        config.setAllowedIssuers("https://issuer.example");
        VerifiedCredential allowed = sdJwtCredential(Map.of("sub", "user1"));
        VerifiedCredential disallowed = new VerifiedCredential(
                "cred-2",
                "https://evil-issuer.example",
                "IdentityCredential",
                Map.of("given_name", "Mallory"),
                PresentationType.SD_JWT);
        Oid4vpCallbackProcessor processor = processor(resultOf(allowed, disallowed));

        assertThatThrownBy(() ->
                        processor.process(requestContext("state", "nonce", "IdentityCredential"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Issuer not allowed: https://evil-issuer.example");
    }

    @Test
    void process_credentialTypeNotConfiguredForRequest_throws() {
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1", "https://issuer.example", "BadType", Map.of("sub", "user1"), PresentationType.SD_JWT);
        Oid4vpCallbackProcessor processor = processor(resultOf(credential));
        RequestedCredential requested = new RequestedCredential(
                "cred-1", FORMAT_SD_JWT_VC, "GoodType", List.of(new RequestedClaim(null, "sub")), List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "GoodType"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Credential type not trusted by this OID4VP IdP");
    }

    @Test
    void process_missingPrincipalClaim_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of())));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing principal claim");
    }

    @Test
    void process_missingPrincipalClaim_withTransientUsers_generatesTransientIdentity() {
        config.setTransientUsersEnabled(true);

        BrokeredIdentityContext result = processor(resultOf(sdJwtCredential(Map.of())))
                .process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getUsername()).startsWith("transient-state-");
        assertThat(result.getId()).isNotBlank();
        assertThat(result.getId()).isNotEqualTo(result.getUsername());
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY))
                .isEqualTo(result.getUsername());
    }

    @Test
    void process_claimMappedSubjectsMatchIgnoringCase() {
        config.setPrincipalAttributes(
                "sd-jwt-credential:family_name, mdoc-credential:eu\\.europa\\.ec\\.eudi\\.pid\\.1.family_name");

        VerifiedCredential sdJwtCredential = new VerifiedCredential(
                "sd-jwt-credential",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("family_name", "ExampleUser"),
                PresentationType.SD_JWT);
        VerifiedCredential mdocCredential = new VerifiedCredential(
                "mdoc-credential",
                "https://issuer.example",
                "IdentityCredential",
                Map.of("eu.europa.ec.eudi.pid.1", Map.of("family_name", "exampleuser")),
                PresentationType.MDOC);

        BrokeredIdentityContext upperResult = processor(resultOf(sdJwtCredential))
                .process(requestContext("state-upper", "nonce-upper"), "vp-upper", null);
        BrokeredIdentityContext lowerResult = processor(resultOf(mdocCredential))
                .process(requestContext("state-lower", "nonce-lower"), "vp-lower", null);

        assertThat(upperResult.getId()).isEqualTo(lowerResult.getId());
    }

    @Test
    void process_mdocSubjectIsNotTakenFromANamespaceTheQueryDidNotAskFor() {
        // The elements of an mDoc are issuer signed, so which namespace they live in is not the
        // verifier's choice. Reading the subject out of any namespace that happens to carry it would
        // let a credential answer with an identity out of a namespace this verifier never asked for.
        config.setPrincipalAttributes("cred-1:sub");
        VerifiedCredential mdoc = new VerifiedCredential(
                "cred-1",
                null,
                "eu.europa.ec.eudi.pid.1",
                Map.of(
                        "eu.europa.ec.eudi.pid.1", Map.of("given_name", "Erika"),
                        "com.example.vendor", Map.of("sub", "an-identity-of-another-namespace")),
                PresentationType.MDOC);
        RequestedCredential requested = new RequestedCredential(
                "cred-1",
                FORMAT_MSO_MDOC,
                "eu.europa.ec.eudi.pid.1",
                List.of(new RequestedClaim("eu.europa.ec.eudi.pid.1", "given_name")),
                List.of());

        assertThatThrownBy(() -> processor(resultOf(mdoc))
                        .process(requestContext("state", "nonce", List.of(requested)), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing principal claim");
    }

    @Test
    void process_namedMdocSubjectClaimAddressesItsNamespaceItself() {
        // Named principal credentials carry the path from the root of the presentation. The
        // namespace is spelled out and nothing about it is inferred.
        config.setPrincipalAttributes("cred-1:com\\.example\\.vendor.sub");
        VerifiedCredential mdoc = new VerifiedCredential(
                "cred-1",
                null,
                "org.iso.18013.5.1.mDL",
                Map.of(
                        "org.iso.18013.5.1", Map.of("sub", "the-other-namespace"),
                        "com.example.vendor", Map.of("sub", "the-named-namespace")),
                PresentationType.MDOC);

        BrokeredIdentityContext result =
                processor(resultOf(mdoc)).process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getUsername()).isEqualTo("the-named-namespace");
    }

    @Test
    void process_rejectsPresentationMissingRequestedClaims() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        RequestedCredential requested = new RequestedCredential(
                "cred-1",
                FORMAT_SD_JWT_VC,
                "IdentityCredential",
                List.of(new RequestedClaim(null, "sub"), new RequestedClaim(null, "given_name")),
                List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("requested claims")
                .hasMessageContaining("given_name");
    }

    // Without credential_sets every requested credential is required (OID4VP 1.0, section 6.1).
    @Test
    void process_rejectsPresentationOmittingARequestedCredential() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        RequestedCredential presented =
                new RequestedCredential("cred-1", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(), List.of());
        RequestedCredential omitted =
                new RequestedCredential("cred-2", FORMAT_SD_JWT_VC, "BadgeCredential", List.of(), List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext(
                                "state", "nonce", List.of(presented, omitted), "IdentityCredential", "BadgeCredential"),
                        "vp-token",
                        null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("missing requested credentials")
                .hasMessageContaining("cred-2");
    }

    @Test
    void process_acceptsPresentationSatisfyingFallbackClaimSet() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        RequestedCredential requested = new RequestedCredential(
                "cred-1",
                FORMAT_SD_JWT_VC,
                "IdentityCredential",
                List.of(new RequestedClaim(null, "sub"), new RequestedClaim(null, "given_name")),
                List.of(List.of(0, 1), List.of(0)));

        BrokeredIdentityContext result = processor.process(
                requestContext("state", "nonce", List.of(requested), "IdentityCredential"), "vp-token", null);

        assertThat(result.getUsername()).isEqualTo("user1");
    }

    @Test
    void process_rejectsPresentationSatisfyingNoClaimSet() {
        Oid4vpCallbackProcessor processor =
                processor(resultOf(sdJwtCredential(Map.of("email", "a@example.org", "sub", "user1"))));
        RequestedCredential requested = new RequestedCredential(
                "cred-1",
                FORMAT_SD_JWT_VC,
                "IdentityCredential",
                List.of(
                        new RequestedClaim(null, "sub"),
                        new RequestedClaim(null, "given_name"),
                        new RequestedClaim(null, "family_name")),
                List.of(List.of(0, 1), List.of(0, 2)));

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("requested claims");
    }

    @Test
    void process_rejectsPresentationSatisfyingNoCredentialSetOption() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        List<CredentialSet> credentialSets = List.of(new CredentialSet(List.of(List.of("cred-1", "mdl")), true, null));

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requestedSub()), credentialSets, "IdentityCredential"),
                        "vp-token",
                        null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("does not satisfy any option")
                .hasMessageContaining("mdl");
    }

    @Test
    void process_acceptsPresentationSatisfyingFallbackCredentialSetOption() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        List<CredentialSet> credentialSets =
                List.of(new CredentialSet(List.of(List.of("cred-1", "mdl"), List.of("cred-1")), true, null));

        BrokeredIdentityContext result = processor.process(
                requestContext("state", "nonce", List.of(requestedSub()), credentialSets, "IdentityCredential"),
                "vp-token",
                null);

        assertThat(result.getUsername()).isEqualTo("user1");
    }

    @Test
    void process_ignoresUnsatisfiedOptionalCredentialSet() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        List<CredentialSet> credentialSets = List.of(
                new CredentialSet(List.of(List.of("cred-1")), true, null),
                new CredentialSet(List.of(List.of("mdl")), false, null));

        BrokeredIdentityContext result = processor.process(
                requestContext("state", "nonce", List.of(requestedSub()), credentialSets, "IdentityCredential"),
                "vp-token",
                null);

        assertThat(result.getUsername()).isEqualTo("user1");
    }

    @Test
    void process_rejectsCredentialIdThatWasNotRequested() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        RequestedCredential requested = new RequestedCredential(
                "other", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(new RequestedClaim(null, "sub")), List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("cred-1")
                .hasMessageContaining("not requested");
    }

    private static RequestedCredential requestedSub() {
        return new RequestedCredential(
                "cred-1", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(new RequestedClaim(null, "sub")), List.of());
    }

    @Test
    void process_subjectCredentialMissing_generatesASubject() {
        // This Keycloak issues the subject credential. A first presentation legitimately arrives
        // without it. The login that follows establishes which user it belongs to.
        config.setPrincipalAttributes("kc:sub");
        config.setAllowMissingSubjectCredential(true);
        RequestedCredential pid = new RequestedCredential(
                "cred-1", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(new RequestedClaim(null, "sub")), List.of());
        RequestedCredential kc = new RequestedCredential(
                "kc",
                FORMAT_SD_JWT_VC,
                "https://kc.example/badge",
                List.of(new RequestedClaim(null, "sub")),
                List.of());

        BrokeredIdentityContext result = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))))
                .process(requestContext("state", "nonce", List.of(pid, kc), "IdentityCredential"), "vp-token", null);

        assertThat(result.getUsername()).startsWith("oid4vp-");
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY))
                .isEqualTo(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY));
    }

    @Test
    void process_subjectCredentialMissingWithoutTheSetting_stillFails() {
        config.setPrincipalAttributes("kc:sub");

        assertThatThrownBy(() -> processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))))
                        .process(requestContext("state", "nonce"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("None of the credentials carrying the subject");
    }

    @Test
    void process_subjectCredentialOfAnotherPresentation_isNotAcceptedAsTheSubject() {
        // The credential belongs to somebody else's presentation and identifies nobody here, so the
        // login continues on the PID alone, as if it had not been presented.
        config.setPrincipalAttributes("cred-1:sub");
        config.setAllowMissingSubjectCredential(true);

        BrokeredIdentityContext result = processor(pidAndCredentialBoundElsewhere(), ISSUED_FOR_ANOTHER_PRESENTATION)
                .process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getUsername()).startsWith("oid4vp-");
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
    }

    @Test
    void process_subjectCredentialOfAnotherPresentation_isNotMappedEither() {
        // A credential this verifier refuses must not reach the mappers. Otherwise the claims of
        // somebody else's credential would be written onto the account that signs in afterwards.
        config.setPrincipalAttributes("cred-1:sub");
        config.setAllowMissingSubjectCredential(true);

        BrokeredIdentityContext result = processor(pidAndCredentialBoundElsewhere(), ISSUED_FOR_ANOTHER_PRESENTATION)
                .process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(Oid4vpMapperUtils.presentedCredentials(result).byCredentialId())
                .containsOnlyKeys("pid");
    }

    @Test
    void process_subjectCredentialOfAnotherPresentationWithoutTheSetting_fails() {
        config.setPrincipalAttributes("cred-1:sub");

        assertThatThrownBy(() -> processor(pidAndCredentialBoundElsewhere(), ISSUED_FOR_ANOTHER_PRESENTATION)
                        .process(requestContext("state", "nonce"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("None of the credentials carrying the subject");
    }

    @Test
    void process_subjectCredentialWithheldBinding_fallsBackToAFreshSubject() {
        // A subject credential this realm issues alongside bindable credentials is always bound to
        // them. One presented next to such credentials but carrying no binding claim has its binding
        // withheld, which happens when the binding claim is left out of the issued credential's
        // visible claims, or when the credential is combined with another holder's PID. It does not
        // identify a returning user, so the login falls back to a fresh subject.
        config.setPrincipalAttributes("cred-1:sub");
        config.setAllowMissingSubjectCredential(true);
        VerifiedCredential subjectCredential = sdJwtCredential(Map.of("sub", "user1"));
        VerifiedCredential otherHoldersPid = new VerifiedCredential(
                "pid",
                "https://pid.example",
                "IdentityCredential",
                Map.of("given_name", "Mallory"),
                PresentationType.SD_JWT);
        ReferenceBindingCheck presentationBindsToOthers = new FixedReferenceBindingCheck(true, true);

        BrokeredIdentityContext result = processor(
                        resultOf(subjectCredential, otherHoldersPid), presentationBindsToOthers)
                .process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getUsername()).startsWith("oid4vp-").isNotEqualToIgnoringCase("user1");
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
    }

    @Test
    void process_subjectCredentialWithheldBinding_withoutFallbackSetting_fails() {
        // Without allowMissingSubjectCredential the presentation has to carry a usable subject
        // credential, and a withheld binding leaves nothing to identify the user.
        config.setPrincipalAttributes("cred-1:sub");
        VerifiedCredential subjectCredential = sdJwtCredential(Map.of("sub", "user1"));
        VerifiedCredential otherHoldersPid = new VerifiedCredential(
                "pid",
                "https://pid.example",
                "IdentityCredential",
                Map.of("given_name", "Mallory"),
                PresentationType.SD_JWT);
        ReferenceBindingCheck presentationBindsToOthers = new FixedReferenceBindingCheck(true, true);

        assertThatThrownBy(() -> processor(resultOf(subjectCredential, otherHoldersPid), presentationBindsToOthers)
                        .process(requestContext("state", "nonce"), "vp-token", null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("None of the credentials carrying the subject");
    }

    private static VpTokenResult pidAndCredentialBoundElsewhere() {
        VerifiedCredential pid = new VerifiedCredential(
                "pid",
                "https://pid.example",
                "IdentityCredential",
                Map.of("given_name", "Erika"),
                PresentationType.SD_JWT);
        VerifiedCredential boundElsewhere = sdJwtCredential(Map.of(
                "sub", "subject-of-another-holder", ReferenceCredentialBinding.REFERENCE_BINDING_CLAIM, "other"));
        Map<String, VerifiedCredential> credentials = new LinkedHashMap<>();
        credentials.put(pid.credentialId(), pid);
        credentials.put(boundElsewhere.credentialId(), boundElsewhere);
        return new VpTokenResult(credentials);
    }

    @Test
    void process_subjectCredentialPresented_usesItsSubjectInsteadOfGeneratingOne() {
        config.setPrincipalAttributes("cred-1:sub");
        config.setAllowMissingSubjectCredential(true);

        BrokeredIdentityContext result = processor(resultOf(sdJwtCredential(Map.of("sub", "oid4vp-generated-earlier"))))
                .process(requestContext("state", "nonce"), "vp-token", null);

        assertThat(result.getUsername()).isEqualToIgnoringCase("oid4vp-generated-earlier");
        assertThat(result.getContextData()).doesNotContainKey(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY);
    }

    @Test
    void generatedSubjectAndCredentialCarriedSubjectResolveToTheSameIdentity() {
        config.setPrincipalAttributes("kc:sub");
        config.setAllowMissingSubjectCredential(true);
        RequestedCredential kc = new RequestedCredential(
                "kc",
                FORMAT_SD_JWT_VC,
                "https://kc.example/badge",
                List.of(new RequestedClaim(null, "sub")),
                List.of());

        BrokeredIdentityContext firstLogin = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))))
                .process(
                        requestContext("state", "nonce", List.of(requestedSub(), kc), "IdentityCredential"),
                        "vp-token",
                        null);
        String generatedSubject = (String) firstLogin.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY);

        config.setPrincipalAttributes("cred-1:sub");
        BrokeredIdentityContext secondLogin = processor(resultOf(sdJwtCredential(Map.of("sub", generatedSubject))))
                .process(requestContext("state-2", "nonce-2"), "vp-token", null);

        assertThat(secondLogin.getId())
                .as("the brokered identity of both logins has to be the same user")
                .isEqualTo(firstLogin.getId());
    }

    private Oid4vpCallbackProcessor processor(VpTokenResult verificationResult) {
        return processor(verificationResult, ISSUED_FOR_THIS_PRESENTATION);
    }

    private Oid4vpCallbackProcessor processor(
            VpTokenResult verificationResult, ReferenceBindingCheck referenceBindingCheck) {
        VpTokenVerifier verifier = request -> verificationResult;
        return new Oid4vpCallbackProcessor(config, config, null, verifier, referenceBindingCheck);
    }

    private record FixedReferenceBindingCheck(boolean bound, boolean bindsToOthers) implements ReferenceBindingCheck {
        @Override
        public boolean boundToPresentation(
                PresentedCredentials credentials, String subjectCredentialId, String claimedBinding) {
            return bound;
        }

        @Override
        public boolean bindsToOtherCredentials(PresentedCredentials credentials, String subjectCredentialId) {
            return bindsToOthers;
        }
    }

    private static final ReferenceBindingCheck ISSUED_FOR_THIS_PRESENTATION =
            new FixedReferenceBindingCheck(true, false);

    private static final ReferenceBindingCheck ISSUED_FOR_ANOTHER_PRESENTATION =
            new FixedReferenceBindingCheck(false, false);

    private static VpTokenResult resultOf(VerifiedCredential credential) {
        return new VpTokenResult(Map.of(credential.credentialId(), credential));
    }

    private static VpTokenResult resultOf(VerifiedCredential... credentials) {
        Map<String, VerifiedCredential> byId = new LinkedHashMap<>();
        for (VerifiedCredential credential : credentials) {
            byId.put(credential.credentialId(), credential);
        }
        return new VpTokenResult(byId);
    }

    private static VerifiedCredential sdJwtCredential(Map<String, Object> claims) {
        return new VerifiedCredential(
                "cred-1", "https://issuer.example", "IdentityCredential", claims, PresentationType.SD_JWT);
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(String state, String nonce) {
        return requestContext(state, nonce, "IdentityCredential");
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String state, String nonce, String... configuredCredentialTypes) {
        return requestContext(state, nonce, null, List.of(), configuredCredentialTypes);
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String state,
            String nonce,
            List<RequestedCredential> requestedCredentials,
            String... configuredCredentialTypes) {
        return requestContext(state, nonce, requestedCredentials, List.of(), configuredCredentialTypes);
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String state,
            String nonce,
            List<RequestedCredential> requestedCredentials,
            List<CredentialSet> credentialSets,
            String... configuredCredentialTypes) {
        return requestContext(state, nonce, FLOW_SAME_DEVICE, requestedCredentials, credentialSets);
    }

    private Oid4vpRequestObjectStore.RequestContextEntry requestContext(
            String state,
            String nonce,
            String flow,
            List<RequestedCredential> requestedCredentials,
            List<CredentialSet> credentialSets) {
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                "root-session",
                "tab-1",
                "test-client",
                "https://example.com/callback",
                flow,
                nonce,
                null,
                null,
                requestedCredentials,
                credentialSets,
                null);
    }
}
