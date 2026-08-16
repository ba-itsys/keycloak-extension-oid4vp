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
package de.arbeitsagentur.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.authentication.Oid4vpSubjectBindingAuthenticator;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestCertificates;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.VciTestWalletConfig;
import de.arbeitsagentur.keycloak.oid4vp.trust.EtsiTrustListIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.trust.KeycloakRealmIssuerIdentityProviderConfig;
import io.github.dominikschlosser.eudi.Credential;
import io.github.dominikschlosser.eudi.CredentialFormat;
import io.github.dominikschlosser.eudi.IssueRequest;
import jakarta.ws.rs.core.Response;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.AuthenticationExecutionRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

/**
 * The subject credential is issued by this Keycloak, so the first presentation arrives without it.
 *
 * <p>The wallet holds the PID alone, which identifies nobody. The user signs in with a password, the
 * login is bound to that user, and the credential offer issues the employee credential carrying a
 * subject derived for that account and the reference credential binding of the PID it was issued
 * alongside. The next presentation carries that credential and reaches the same account without a
 * password.
 */
@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpIssuedSubjectCredentialE2eIT extends AbstractOid4vpE2eTest {

    private static final String EMPLOYEE_VCT = "https://kc.example/employee";
    private static final String EMPLOYEE_CREDENTIAL_ID = "employee";
    private static final String CREDENTIAL_CONFIGURATION_ID = "employee-credential";
    private static final String CREDENTIAL_SCOPE = "employee-credential";
    private static final String VCI_CLIENT_ID = VciTestWalletConfig.VCI_CLIENT_ID;
    private static final String USERNAME = "wallet-user";
    private static final String PASSWORD = "wallet-password";
    private static final String FIRST_BROKER_LOGIN_FLOW = "oid4vp first broker login";
    private static final String REALM_ISSUER_TRUST_ALIAS = "keycloak-realm-issuer";
    private static final String KEY_PROVIDER_NAME = "oid4vp-issuer-signing-key";

    @InjectTestWallet(config = VciTestWalletConfig.class)
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void aPidOnlyLoginIssuesTheSubjectCredentialAndTheNextLoginUsesIt() throws Exception {
        startFromAWalletHoldingThePidAlone();

        // The wallet holds the PID alone, so the presentation carries no subject
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        Oid4vpLoginFlowHelper.WalletResponse walletResponse = flow.submitToWallet(flow.getSameDeviceWalletUrl());
        flow.waitForLoginCompletion(walletResponse);

        signInWithPassword();
        acceptTheCredentialOffer();
        flow.assertLoginSucceeded();

        Credential issued = issuedCredential();
        assertThat(issued.claims().get("sub"))
                .as("the issued credential carries a subject of its own, never the Keycloak user id")
                .isNotNull()
                .isNotEqualTo(userId());
        assertThat(issued.claims())
                .as("the credential says which presentation it was issued for")
                .containsKey("oid4vp_reference_binding");

        // The next presentation carries the issued credential, which identifies the user
        testApp().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        Oid4vpLoginFlowHelper.WalletResponse secondResponse = flow.submitToWallet(flow.getSameDeviceWalletUrl());
        flow.waitForLoginCompletion(secondResponse);

        assertThat(page.locator("input[name='password']").count())
                .as("the issued credential identifies the user, so no password is asked for")
                .isZero();
        flow.assertLoginSucceeded();
    }

    /**
     * The user can always lose the credential this Keycloak issued, or decline to present it. The
     * login then arrives without a subject a second time, for a user who is already linked to this
     * identity provider.
     */
    @Test
    void aUserWhoLostTheIssuedCredentialSignsInWithAPasswordAndReceivesANewOne() throws Exception {
        startFromAWalletHoldingThePidAlone();

        firstPidOnlyLogin();
        String firstSubject = issuedCredential().claims().get("sub").toString();

        // The user deletes it from the wallet, so the next presentation carries the PID alone again
        wallet().client().deleteCredentialsByType(EMPLOYEE_VCT);
        testApp().reset();
        flow.clearBrowserSession();

        firstPidOnlyLogin();

        assertThat(issuedCredential().claims().get("sub"))
                .as("the subject is derived from the account, so the replacement reaches the same identity")
                .isEqualTo(firstSubject);

        // And that replacement identifies the user again, without a password
        testApp().reset();
        flow.clearBrowserSession();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.waitForLoginCompletion(flow.submitToWallet(flow.getSameDeviceWalletUrl()));

        assertThat(page.locator("input[name='password']").count())
                .as("the replacement credential identifies the user like the first one did")
                .isZero();
        flow.assertLoginSucceeded();
    }

    /**
     * The credential this Keycloak issues identifies an account on its own, so it may not sign in
     * next to the PID of somebody else. Without the reference credential binding a wallet holding
     * the credentials of two people would do exactly that.
     */
    @Test
    void theIssuedCredentialDoesNotSignInNextToThePidOfSomebodyElse() throws Exception {
        startFromAWalletHoldingThePidAlone();

        firstPidOnlyLogin();
        assertThat(issuedCredential().claims())
                .as("the credential says which presentation it was issued for")
                .containsKey("oid4vp_reference_binding");

        // The wallet keeps the credential but now holds the PID of another person
        wallet().client().deleteCredentialsByType(Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT);
        wallet().client()
                .issueCredential(IssueRequest.pid(CredentialFormat.SD_JWT)
                        .claim("given_name", "Max")
                        .claim("family_name", "Andersson")
                        .claim("birthdate", "1979-03-04"));
        testApp().reset();
        flow.clearBrowserSession();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.waitForLoginCompletion(flow.submitToWallet(flow.getSameDeviceWalletUrl()));

        page.waitForSelector("input[name='password']");
        assertThat(page.locator("input[name='password']").count())
                .as("the credential was issued for another person's PID, so it identifies nobody here")
                .isPositive();
    }

    /**
     * The state this scenario starts in: no account yet, and a wallet that does not hold the
     * credential this Keycloak issues. A credential issued by an earlier test would otherwise be
     * presented and identify nobody, since the account behind it is gone.
     */
    private void startFromAWalletHoldingThePidAlone() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        wallet().client().deleteCredentialsByType(EMPLOYEE_VCT);

        configureIssuer();
        configureVerifier();
    }

    /** A login the wallet answers with the PID alone, ending in the issued credential. */
    private void firstPidOnlyLogin() {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        flow.waitForLoginCompletion(flow.submitToWallet(flow.getSameDeviceWalletUrl()));
        signInWithPassword();
        acceptTheCredentialOffer();
        flow.assertLoginSucceeded();
    }

    private Credential issuedCredential() {
        return wallet().client().getCredentials().stream()
                .filter(credential -> EMPLOYEE_VCT.equals(credential.type()))
                .findFirst()
                .orElseThrow(
                        () -> new AssertionError("the wallet did not receive the credential this Keycloak issued"));
    }

    private String userId() {
        return realm.admin().users().searchByUsername(USERNAME, true).stream()
                .findFirst()
                .orElseThrow()
                .getId();
    }

    private void signInWithPassword() {
        page.waitForSelector("input[name='password']");
        page.locator("input[name='username']").fill(USERNAME);
        page.locator("input[name='password']").fill(PASSWORD);
        page.locator("input[type='submit'], button[type='submit']").first().click();
        page.waitForLoadState();
    }

    private void acceptTheCredentialOffer() {
        page.waitForSelector("#credential-offer-uri-link");
        String offerUri = page.locator("#credential-offer-uri-link").getAttribute("href");
        assertThat(offerUri)
                .as("the required action offers the subject credential")
                .isNotBlank();

        wallet().client().acceptCredentialOffer(offerUri);

        page.locator("#continue-vc-offer").click();
        page.waitForLoadState();
    }

    /** The issuer side: a signing key a certificate authority issued, a credential scope, a client. */
    private void configureIssuer() throws Exception {
        enableVerifiableCredentials();
        addIssuerSigningKey();
        addCredentialScope();
        addVciClient();
        addUser();
    }

    /** The OID4VC protocol is refused for a realm that does not have verifiable credentials on. */
    private void enableVerifiableCredentials() {
        RealmRepresentation realmRepresentation = realm.admin().toRepresentation();
        if (Boolean.TRUE.equals(realmRepresentation.isVerifiableCredentialsEnabled())) {
            return;
        }
        realmRepresentation.setVerifiableCredentialsEnabled(true);
        realm.admin().update(realmRepresentation);
    }

    /**
     * Keycloak refuses to issue an SD-JWT credential with a self-signed signing certificate, so the
     * realm needs a key whose certificate a certificate authority issued.
     */
    private void addIssuerSigningKey() throws Exception {
        if (!realm.admin()
                .components()
                .query(realm.getId(), "org.keycloak.keys.KeyProvider", KEY_PROVIDER_NAME)
                .isEmpty()) {
            return;
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair certificateAuthority = generator.generateKeyPair();
        KeyPair signingKey = generator.generateKeyPair();
        X509Certificate authorityCertificate = selfSignedAuthority(certificateAuthority);
        X509Certificate signingCertificate = issuedLeaf(signingKey, certificateAuthority, authorityCertificate);

        ComponentRepresentation component = new ComponentRepresentation();
        component.setName(KEY_PROVIDER_NAME);
        component.setProviderId("rsa");
        component.setProviderType("org.keycloak.keys.KeyProvider");
        component.setParentId(realm.getId());
        component.setConfig(new MultivaluedHashMap<>(Map.of(
                "privateKey",
                        List.of(TestCertificates.toPem(
                                "PRIVATE KEY", signingKey.getPrivate().getEncoded())),
                "certificate", List.of(TestCertificates.toPem("CERTIFICATE", signingCertificate.getEncoded())),
                "active", List.of("true"),
                "enabled", List.of("true"),
                "priority", List.of("200"),
                "algorithm", List.of("RS256"),
                "keyUse", List.of("SIG"))));
        realm.admin().components().add(component).close();
    }

    private void addCredentialScope() {
        if (realm.admin().clientScopes().findAll().stream()
                .anyMatch(scope -> CREDENTIAL_SCOPE.equals(scope.getName()))) {
            return;
        }
        ProtocolMapperRepresentation subjectId = new ProtocolMapperRepresentation();
        subjectId.setName("employee-subject-id");
        subjectId.setProtocol("oid4vc");
        subjectId.setProtocolMapper("oid4vp-bound-subject-mapper");
        subjectId.setConfig(Map.of("claim.name", "sub"));

        ClientScopeRepresentation scope = new ClientScopeRepresentation();
        scope.setName(CREDENTIAL_SCOPE);
        scope.setProtocol("oid4vc");
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("vc.credential_configuration_id", CREDENTIAL_CONFIGURATION_ID);
        attributes.put("vc.credential_identifier", CREDENTIAL_CONFIGURATION_ID);
        attributes.put("vc.verifiable_credential_type", EMPLOYEE_VCT);
        attributes.put("vc.format", "dc+sd-jwt");
        attributes.put("vc.credential_signing_alg", "RS256");
        attributes.put("vc.include_in_metadata", "true");
        // The wallet proves possession of its key, so the credential it receives is bound to it
        // and can be presented with a key binding JWT
        attributes.put("vc.cryptographic_binding_methods_supported", "jwk");
        attributes.put("vc.binding_required", "true");
        attributes.put("vc.binding_required_proof_types", "jwt");
        // The verifier reads the reference credential binding of every presented credential, so it may not be
        // hidden behind selective disclosure
        // The claims Keycloak keeps visible by default have to stay in the list, it replaces them
        attributes.put(
                "vc.credential_build_config.sd_jwt.visible_claims", "id,iat,nbf,exp,jti,oid4vp_reference_binding");
        attributes.put("vc.expiry_in_seconds", "31536000");
        attributes.put("include.in.token.scope", "true");
        scope.setAttributes(attributes);
        assertCreated("credential scope", realm.admin().clientScopes().create(scope));
        String scopeId = realm.admin().clientScopes().findAll().stream()
                .filter(created -> CREDENTIAL_SCOPE.equals(created.getName()))
                .findFirst()
                .orElseThrow()
                .getId();
        assertCreated(
                "subject id mapper",
                realm.admin().clientScopes().get(scopeId).getProtocolMappers().createMapper(subjectId));
    }

    private void addVciClient() {
        if (realm.admin().clients().findByClientId(VCI_CLIENT_ID).stream()
                .findAny()
                .isPresent()) {
            return;
        }
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(VCI_CLIENT_ID);
        client.setEnabled(true);
        client.setPublicClient(true);
        client.setProtocol("openid-connect");
        client.setRedirectUris(List.of("*"));
        client.setAttributes(Map.of("oid4vci.enabled", "true"));
        client.setOptionalClientScopes(List.of(CREDENTIAL_SCOPE));
        assertCreated("vci client", realm.admin().clients().create(client));
    }

    private void addUser() {
        if (!realm.admin().users().searchByUsername(USERNAME, true).isEmpty()) {
            return;
        }
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(PASSWORD);
        password.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(USERNAME);
        user.setEnabled(true);
        user.setEmail(USERNAME + "@example.com");
        user.setEmailVerified(true);
        user.setFirstName("Wallet");
        user.setLastName("User");
        user.setCredentials(List.of(password));
        assertCreated("user", realm.admin().users().create(user));
    }

    /** The verifier side: the credential set, the trust of the issued credential, the login flow. */
    private void configureVerifier() {
        addFirstBrokerLoginFlow();
        addRealmIssuerTrustProvider();

        List<IdentityProviderMapperRepresentation> mappers = new ArrayList<>(Oid4vpTestKeycloakSetup.sdJwtPidMappers());
        IdentityProviderMapperRepresentation employeeSubject = Oid4vpTestKeycloakSetup.sdJwtSessionMapper(
                "employee-subject", EMPLOYEE_VCT, "sub", "employeeSubject", null);
        employeeSubject.getConfig().put("credential.id", EMPLOYEE_CREDENTIAL_ID);
        mappers.add(employeeSubject);
        replaceDcqlMappers(mappers);

        setTrustIdpConfig(Map.of(
                EtsiTrustListIdentityProviderConfig.SERVED_CREDENTIAL_TYPES, Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT));

        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.CREDENTIAL_SETS,
                "[{\"options\": [[\"" + Oid4vpTestKeycloakSetup.SD_JWT_PID_CREDENTIAL_ID + "\", \""
                        + EMPLOYEE_CREDENTIAL_ID + "\"], [\""
                        + Oid4vpTestKeycloakSetup.SD_JWT_PID_CREDENTIAL_ID + "\"]]}]",
                Oid4vpIdentityProviderConfig.PRINCIPAL_ATTRIBUTES,
                EMPLOYEE_CREDENTIAL_ID + ":sub",
                Oid4vpIdentityProviderConfig.ALLOW_MISSING_SUBJECT_CREDENTIAL,
                "true",
                Oid4vpIdentityProviderConfig.TRUST_MATERIAL_IDPS,
                Oid4vpTestKeycloakSetup.TRUST_IDP_ALIAS + "," + REALM_ISSUER_TRUST_ALIAS));

        realm.updateIdentityProvider(
                Oid4vpTestKeycloakSetup.IDP_ALIAS, idp -> idp.setFirstBrokerLoginFlowAlias(FIRST_BROKER_LOGIN_FLOW));
    }

    /**
     * The PID matches no account, so the default flow would create a user. This flow asks the user
     * to sign in and binds the login to that user instead.
     */
    private void addFirstBrokerLoginFlow() {
        boolean exists = realm.admin().flows().getFlows().stream()
                .anyMatch(flow -> FIRST_BROKER_LOGIN_FLOW.equals(flow.getAlias()));
        if (exists) {
            return;
        }
        AuthenticationFlowRepresentation loginFlow = new AuthenticationFlowRepresentation();
        loginFlow.setAlias(FIRST_BROKER_LOGIN_FLOW);
        loginFlow.setProviderId("basic-flow");
        loginFlow.setTopLevel(true);
        loginFlow.setBuiltIn(false);
        assertCreated("first broker login flow", realm.admin().flows().createFlow(loginFlow));
        addExecution("idp-username-password-form", 10);
        String bindingExecutionId = addExecution("oid4vp-subject-binding", 20);
        configureSubjectBinding(bindingExecutionId);
    }

    /** The offer is configured on the authenticator, which is where the login is bound to the user. */
    private void configureSubjectBinding(String executionId) {
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias("oid4vp-subject-binding-config");
        config.setConfig(Map.of(
                Oid4vpSubjectBindingAuthenticator.CREDENTIAL_CONFIGURATION_ID,
                CREDENTIAL_CONFIGURATION_ID,
                Oid4vpSubjectBindingAuthenticator.OFFER_CLIENT_ID,
                VCI_CLIENT_ID));
        assertCreated("subject binding config", realm.admin().flows().newExecutionConfig(executionId, config));
    }

    private String addExecution(String provider, int priority) {
        AuthenticationExecutionRepresentation execution = new AuthenticationExecutionRepresentation();
        execution.setParentFlow(realm.admin().flows().getFlows().stream()
                .filter(flow -> FIRST_BROKER_LOGIN_FLOW.equals(flow.getAlias()))
                .findFirst()
                .orElseThrow()
                .getId());
        execution.setAuthenticator(provider);
        execution.setRequirement("REQUIRED");
        execution.setPriority(priority);
        execution.setAutheticatorFlow(false);
        assertCreated("execution " + provider, realm.admin().flows().addExecution(execution));
        return realm.admin().flows().getExecutions(FIRST_BROKER_LOGIN_FLOW).stream()
                .filter(created -> provider.equals(created.getProviderId()))
                .findFirst()
                .orElseThrow()
                .getId();
    }

    /** Trusts the credential this Keycloak issues, through the keys of the issuing realm. */
    private void addRealmIssuerTrustProvider() {
        boolean exists = realm.admin().identityProviders().findAll().stream()
                .anyMatch(idp -> REALM_ISSUER_TRUST_ALIAS.equals(idp.getAlias()));
        if (exists) {
            return;
        }
        IdentityProviderRepresentation trustIdp = new IdentityProviderRepresentation();
        trustIdp.setAlias(REALM_ISSUER_TRUST_ALIAS);
        trustIdp.setDisplayName("Keycloak Realm Issuer");
        trustIdp.setProviderId("keycloak-realm-issuer");
        trustIdp.setEnabled(true);
        trustIdp.setConfig(Map.of(KeycloakRealmIssuerIdentityProviderConfig.SERVED_CREDENTIAL_TYPES, EMPLOYEE_VCT));
        assertCreated(
                "realm issuer trust provider", realm.admin().identityProviders().create(trustIdp));
    }

    /** Reports what the server refused, which a bare status code does not say. */
    private static void assertCreated(String what, Response response) {
        try (response) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            assertThat(response.getStatus())
                    .as("creating the %s failed: %s", what, body)
                    .isLessThan(400);
        }
    }

    private static X509Certificate selfSignedAuthority(KeyPair authority) throws Exception {
        X500Principal subject = new X500Principal("CN=Issuer Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                authority.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(authority.getPrivate())));
    }

    private static X509Certificate issuedLeaf(KeyPair leaf, KeyPair authority, X509Certificate authorityCertificate)
            throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                authorityCertificate.getSubjectX500Principal(),
                BigInteger.valueOf(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Principal("CN=OID4VP Issuer"),
                leaf.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(authority.getPrivate())));
    }
}
