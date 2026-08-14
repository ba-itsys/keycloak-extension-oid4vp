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

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.FORMAT_SD_JWT_VC;
import static org.assertj.core.api.Assertions.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential.RequestedClaim;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenVerifier;
import java.time.Instant;
import java.util.Date;
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
 * configuration and canned verification results; the verification pipeline itself is covered by
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
        config.setEnforceHaip(false);
        config.setPrincipalAttribute("sub");
    }

    @Test
    void process_validSdJwt_returnsBrokeredIdentityContext() {
        VerifiedCredential credential = sdJwtCredential(Map.of("sub", "user1"));

        BrokeredIdentityContext result = processor(resultOf(credential))
                .process(requestContext("test-state", "test-nonce"), "vp-token", null, null);

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
    void process_missingRequestContext_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(null, "token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing request context");
    }

    @Test
    void process_missingVpToken_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), null, null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing vp_token");
    }

    @Test
    void process_issuerNotAllowed_throws() {
        config.setAllowedIssuers("https://trusted-issuer.example");
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), "vp-token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Issuer not allowed");
    }

    @Test
    void process_credentialTypeNotConfiguredForRequest_throws() {
        VerifiedCredential credential = new VerifiedCredential(
                "cred-1", "https://issuer.example", "BadType", Map.of("sub", "user1"), PresentationType.SD_JWT);
        Oid4vpCallbackProcessor processor = processor(resultOf(credential));
        RequestedCredential requested = new RequestedCredential(
                "cred-1", FORMAT_SD_JWT_VC, "GoodType", List.of(new RequestedClaim(null, "sub")), List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "GoodType"), "vp-token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Credential type not trusted by this OID4VP IdP");
    }

    @Test
    void process_missingPrincipalClaim_throws() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of())));

        assertThatThrownBy(() -> processor.process(requestContext("state", "nonce"), "vp-token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("Missing principal claim");
    }

    @Test
    void process_missingPrincipalClaim_withTransientUsers_generatesTransientIdentity() {
        config.setTransientUsersEnabled(true);

        BrokeredIdentityContext result = processor(resultOf(sdJwtCredential(Map.of())))
                .process(requestContext("state", "nonce"), "vp-token", null, null);

        assertThat(result.getUsername()).startsWith("transient-state-");
        assertThat(result.getId()).isNotBlank();
        assertThat(result.getId()).isNotEqualTo(result.getUsername());
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY))
                .isEqualTo(result.getUsername());
    }

    @Test
    void process_transientUsersEnabled_ignoresIdTokenSubjectMode() {
        config.setTransientUsersEnabled(true);
        config.setUseIdTokenSubject(true);

        BrokeredIdentityContext result = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))))
                .process(requestContext("state", "nonce"), "vp-token", null, null);

        assertThat(result.getUsername()).startsWith("transient-state-");
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY))
                .isEqualTo(result.getUsername());
    }

    @Test
    void process_withIdTokenSubject_usesJwkThumbprintAsSub() throws Exception {
        config.setUseIdTokenSubject(true);

        VerifiedCredential credential = sdJwtCredential(Map.of("sub", "user1"));
        ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
        String idToken = buildSelfIssuedIdToken(walletKey, "test-client", "test-nonce");

        BrokeredIdentityContext result = processor(resultOf(credential))
                .process(requestContext("test-state", "test-nonce"), "dummy-vp-token", idToken, null);

        String expectedSub = walletKey.computeThumbprint("SHA-256").toString();
        String expectedIdentityKey = credential.generateIdentityKey(expectedSub);
        // BrokeredIdentityContext lowercases the username internally
        assertThat(result.getUsername()).isEqualToIgnoringCase(expectedSub);
        assertThat(result.getId()).isEqualTo(expectedIdentityKey);
        assertThat(result.getContextData().get(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY))
                .isEqualTo(expectedSub);
        assertThat(result.getContextData()).containsKey(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY);
    }

    @Test
    void process_idTokenSubjectEnabled_noIdToken_throws() {
        config.setUseIdTokenSubject(true);
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));

        assertThatThrownBy(() ->
                        processor.process(requestContext("test-state", "test-nonce"), "dummy-vp-token", null, null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("no id_token received");
    }

    // The same user presents an SD-JWT and an mDoc credential whose principal values differ only
    // in casing; both logins must resolve to the same brokered identity. The mDoc principal is
    // found by looking the element up in the presented namespace.
    @Test
    void process_claimMappedSubjectsMatchIgnoringCase() {
        config.setPrincipalAttribute("family_name");

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
                .process(requestContext("state-upper", "nonce-upper"), "vp-upper", null, null);
        BrokeredIdentityContext lowerResult = processor(resultOf(mdocCredential))
                .process(requestContext("state-lower", "nonce-lower"), "vp-lower", null, null);

        assertThat(upperResult.getId()).isEqualTo(lowerResult.getId());
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
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"),
                        "vp-token",
                        null,
                        null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("requested claims")
                .hasMessageContaining("given_name");
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
                requestContext("state", "nonce", List.of(requested), "IdentityCredential"), "vp-token", null, null);

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
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"),
                        "vp-token",
                        null,
                        null))
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
                        null,
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
                null,
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
                null,
                null);

        assertThat(result.getUsername()).isEqualTo("user1");
    }

    @Test
    void process_rejectsCredentialIdThatWasNotRequested() {
        Oid4vpCallbackProcessor processor = processor(resultOf(sdJwtCredential(Map.of("sub", "user1"))));
        RequestedCredential requested = new RequestedCredential(
                "other", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(new RequestedClaim(null, "sub")), List.of());

        assertThatThrownBy(() -> processor.process(
                        requestContext("state", "nonce", List.of(requested), "IdentityCredential"),
                        "vp-token",
                        null,
                        null))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessageContaining("cred-1")
                .hasMessageContaining("not requested");
    }

    private static RequestedCredential requestedSub() {
        return new RequestedCredential(
                "cred-1", FORMAT_SD_JWT_VC, "IdentityCredential", List.of(new RequestedClaim(null, "sub")), List.of());
    }

    // ===== Helper Methods =====

    private Oid4vpCallbackProcessor processor(VpTokenResult verificationResult) {
        VpTokenVerifier verifier = request -> verificationResult;
        return new Oid4vpCallbackProcessor(config, config, null, verifier);
    }

    private static VpTokenResult resultOf(VerifiedCredential credential) {
        return new VpTokenResult(Map.of(credential.credentialId(), credential), Map.of());
    }

    private static VerifiedCredential sdJwtCredential(Map<String, Object> claims) {
        return new VerifiedCredential(
                "cred-1", "https://issuer.example", "IdentityCredential", claims, PresentationType.SD_JWT);
    }

    private String buildSelfIssuedIdToken(ECKey walletKey, String audience, String nonce) throws Exception {
        String thumbprint = walletKey.computeThumbprint("SHA-256").toString();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(thumbprint)
                .subject(thumbprint)
                .audience(audience)
                .claim("nonce", nonce)
                .claim("sub_jwk", walletKey.toPublicJWK().toJSONObject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(walletKey));
        return jwt.serialize();
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
        return new Oid4vpRequestObjectStore.RequestContextEntry(
                state,
                "root-session",
                "tab-1",
                "test-client",
                "https://example.com/callback",
                "same_device",
                nonce,
                null,
                null,
                requestedCredentials,
                credentialSets);
    }
}
