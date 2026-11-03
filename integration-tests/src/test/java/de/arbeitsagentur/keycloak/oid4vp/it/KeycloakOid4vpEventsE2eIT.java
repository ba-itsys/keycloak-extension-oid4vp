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

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.event.Oid4vpEventDetails;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.InjectTestWallet;
import de.arbeitsagentur.keycloak.oid4vp.it.framework.TestWallet;
import java.net.http.HttpClient;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

@KeycloakIntegrationTest(config = Oid4vpServerConfig.class)
class KeycloakOid4vpEventsE2eIT extends AbstractOid4vpE2eTest {

    @InjectTestWallet
    TestWallet wallet;

    @Override
    protected TestWallet wallet() {
        return wallet;
    }

    @Test
    void verifiedPresentationReachesTheEventStore() throws Exception {
        login("event-verified");
        flow.assertLoginSucceeded();

        EventRepresentation event = eventsOfType("PRESENTATION_VERIFIED", 1).get(0);
        assertThat(event.getType()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE.name());
        assertThat(event.getDetails())
                .containsEntry(Oid4vpEventDetails.CREDENTIAL_TYPES, Oid4vpTestKeycloakSetup.SD_JWT_PID_VCT)
                .containsKey(Oid4vpEventDetails.STATE)
                .containsEntry(Oid4vpEventDetails.FLOW, "same_device");
    }

    @Test
    void revokedCredentialFiresDetectedAndFailedWithTheSameState() throws Exception {
        assertRevokedCredentialIsRejected("SD-JWT");

        String state =
                eventsOfType("REVOCATION_DETECTED", 1).get(0).getDetails().get(Oid4vpEventDetails.STATE);
        assertThat(eventsOfType("PRESENTATION_FAILED", 1)).anySatisfy(event -> assertThat(event.getDetails())
                .containsEntry(Oid4vpEventDetails.STATE, state)
                .containsEntry(Oid4vpEventDetails.ORIGIN, "VERIFIER"));
    }

    @Test
    void revokedCredentialNamesTheStatusList() throws Exception {
        assertRevokedCredentialIsRejected("SD-JWT");

        assertThat(eventsOfType("REVOCATION_DETECTED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.MECHANISM, "STATUS_LIST")
                .hasEntrySatisfying(Oid4vpEventDetails.REFERENCE, reference -> assertThat(reference)
                        .contains(" index "));
    }

    @Test
    void walletErrorFailsThePresentationWithItsCode() throws Exception {
        String walletUrl = openWalletPage();
        SignedJWT requestObject = fetchRequestObject(walletUrl);
        String state = requestObject.getJWTClaimsSet().getStringClaim("state");
        String response = encryptWalletResponse(
                ECKey.parse(encryptionJwkOf(requestObject)), Map.of("state", state, "error", "access_denied"));

        postDirectPost(HttpClient.newHttpClient(), responseUri(), "response=" + urlEncode(response));

        assertThat(eventsOfType("PRESENTATION_FAILED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.ORIGIN, "WALLET")
                .containsEntry(Oid4vpEventDetails.ERROR, "access_denied")
                .containsEntry(Oid4vpEventDetails.STATE, state);
    }

    @Test
    void unencryptedPostFailsThePresentationInTransport() throws Exception {
        SignedJWT requestObject = fetchRequestObject(openWalletPage());
        String state = requestObject.getJWTClaimsSet().getStringClaim("state");

        postDirectPost(HttpClient.newHttpClient(), responseUri(), "state=" + urlEncode(state) + "&error=access_denied");

        assertThat(eventsOfType("PRESENTATION_FAILED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.ORIGIN, "TRANSPORT")
                .containsEntry(Oid4vpEventDetails.STATE, state);
    }

    @Test
    void completionWithAWrongResponseCodeIsRejected() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        String state = flow.getState();
        flow.submitToWallet(walletUrl);

        openInAnotherBrowser(keycloakUrls.getBase() + "/realms/" + REALM
                + "/broker/oid4vp/endpoint/complete-auth?state=" + urlEncode(state) + "&response_code=wrong");

        assertThat(eventsOfType("COMPLETION_REJECTED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.REJECTION, "RESPONSE_CODE")
                .containsEntry(Oid4vpEventDetails.STATE, state);
    }

    @Test
    void failureLinkWithAWrongResponseCodeIsRejected() throws Exception {
        String state = fetchRequestObject(openWalletPage()).getJWTClaimsSet().getStringClaim("state");

        page.navigate(keycloakUrls.getBase() + "/realms/" + REALM + "/broker/oid4vp/endpoint/failed?state="
                + urlEncode(state) + "&response_code=wrong");

        assertThat(eventsOfType("COMPLETION_REJECTED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.REJECTION, "RESPONSE_CODE")
                .containsEntry(Oid4vpEventDetails.STATE, state);
    }

    @Test
    void completionWithoutAResponseCodeIsRejected() throws Exception {
        openInAnotherBrowser(keycloakUrls.getBase() + "/realms/" + REALM + "/broker/oid4vp/endpoint/complete-auth");

        assertThat(eventsOfType("COMPLETION_REJECTED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.REJECTION, "RESPONSE_CODE");
    }

    @Test
    void completionFromAnotherBrowserIsRejected() throws Exception {
        String redirectUri = flow.submitToWallet(openWalletPage()).redirectUri();

        openInAnotherBrowser(redirectUri);

        assertThat(eventsOfType("COMPLETION_REJECTED", 1).get(0).getDetails())
                .containsEntry(Oid4vpEventDetails.REJECTION, "BROWSER_MISMATCH");
    }

    @Test
    void levelWithoutAFlowRefusesThePresentation() throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        setIdpConfig(Map.of(
                Oid4vpIdentityProviderConfig.SAME_DEVICE_LOA, "3",
                Oid4vpIdentityProviderConfig.CROSS_DEVICE_LOA, "3"));

        flow.navigateToLoginPage(Map.of("acr_values", "STORK-QAA-Level-4"));
        flow.clickOid4vpIdpButton();

        EventRepresentation event = eventsOfType("PRESENTATION_REFUSED", 1).get(0);
        assertThat(event.getType()).isEqualTo(EventType.IDENTITY_PROVIDER_LOGIN_ERROR.name());
        assertThat(event.getDetails()).containsEntry(Oid4vpEventDetails.REFUSAL, "LEVEL_NOT_OFFERED");
    }

    private String openWalletPage() {
        testApp().reset();
        flow.clearBrowserSession();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        return flow.getSameDeviceWalletUrl();
    }

    private void openInAnotherBrowser(String url) {
        var otherContext = newBrowserContext();
        var otherPage = otherContext.newPage();
        try {
            otherPage.navigate(url);
            otherPage.waitForLoadState();
        } finally {
            otherPage.close();
            otherContext.close();
        }
    }

    private void login(String usernamePrefix) throws Exception {
        testApp().reset();
        flow.clearBrowserSession();
        deleteAllOid4vpUsers();
        performSameDeviceLogin(usernamePrefix);
    }
}
