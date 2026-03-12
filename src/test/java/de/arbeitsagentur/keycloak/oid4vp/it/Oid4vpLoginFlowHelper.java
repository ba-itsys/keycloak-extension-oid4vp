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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitForSelectorState;
import com.nimbusds.jwt.SignedJWT;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Oid4vpLoginFlowHelper {

    private static final Logger LOG = LoggerFactory.getLogger(Oid4vpLoginFlowHelper.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final Page page;
    private final BrowserContext context;
    private final Oid4vcContainer wallet;
    private final String kcHostUrl;
    private final String callbackUrl;
    private final String realm;
    private String lastCrossDeviceRequestHandle;

    Oid4vpLoginFlowHelper(
            Page page,
            BrowserContext context,
            Oid4vcContainer wallet,
            String kcHostUrl,
            String callbackUrl,
            String realm) {
        this.page = page;
        this.context = context;
        this.wallet = wallet;
        this.kcHostUrl = kcHostUrl;
        this.callbackUrl = callbackUrl;
        this.realm = realm;
    }

    void navigateToLoginPage() {
        page.navigate(buildAuthRequestUri().toString());
        page.waitForLoadState(LoadState.NETWORKIDLE);
    }

    void clickOid4vpIdpButton() {
        page.locator("a#social-oid4vp").click();
    }

    String getSameDeviceWalletUrl() {
        page.waitForSelector(
                "a:has-text('Open Wallet App')",
                new Page.WaitForSelectorOptions()
                        .setState(WaitForSelectorState.VISIBLE)
                        .setTimeout(30000));
        String walletUrl = page.locator("a:has-text('Open Wallet App')").getAttribute("href");
        assertThat(walletUrl).as("Wallet URL should be present").isNotEmpty();
        return walletUrl;
    }

    String getCrossDeviceWalletUrl() {
        page.waitForSelector(
                "img[alt='QR Code for wallet login']",
                new Page.WaitForSelectorOptions()
                        .setState(WaitForSelectorState.VISIBLE)
                        .setTimeout(30000));
        String walletUrl = (String)
                page.evaluate(
                        "() => document.querySelector('img[alt=\"QR Code for wallet login\"]').getAttribute('data-wallet-url')");
        assertThat(walletUrl).as("Cross-device wallet URL should be present").isNotEmpty();
        lastCrossDeviceRequestHandle = extractRequestHandleFromRequestUri(extractRequestUri(walletUrl));
        return walletUrl;
    }

    PresentationResponse submitToWallet(String walletUrl) {
        String presentationUri = convertToOpenid4vpUri(walletUrl);
        PresentationResponse response = wallet.acceptPresentationRequest(presentationUri);
        if (isSessionExpiredResponse(response.rawBody())) {
            LOG.info("[Test] Wallet callback raced request-context visibility; retrying same presentation once");
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            response = wallet.acceptPresentationRequest(presentationUri);
        }
        LOG.info("[Test] Wallet response: {}", response.rawBody());
        return response;
    }

    private boolean isSessionExpiredResponse(String rawBody) {
        if (rawBody == null || rawBody.isBlank()) {
            return false;
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(rawBody);
            JsonNode responseNode = root.path("response");
            if (responseNode.path("status_code").asInt(-1) != 400) {
                return false;
            }
            String nestedBody = responseNode.path("body").asText(null);
            if (nestedBody == null || nestedBody.isBlank()) {
                return false;
            }
            JsonNode nestedJson = OBJECT_MAPPER.readTree(nestedBody);
            return "session_expired".equals(nestedJson.path("error").asText());
        } catch (Exception e) {
            return false;
        }
    }

    void waitForSseConnection() {
        LOG.info("[Test] Cross-device flow uses durable completion state; skipping pre-wallet SSE readiness wait");
    }

    String getRequestHandle() {
        String crossDeviceRequestHandle =
                (String) page.evaluate("() => document.querySelector('#crossDeviceRequestHandle')?.value ?? ''");
        if (crossDeviceRequestHandle != null && !crossDeviceRequestHandle.isBlank()) {
            return crossDeviceRequestHandle;
        }
        String requestHandle = (String) page.evaluate("() => document.querySelector('#requestHandle')?.value ?? ''");
        if (requestHandle != null && !requestHandle.isBlank()) {
            return requestHandle;
        }
        return lastCrossDeviceRequestHandle;
    }

    void waitForLoginCompletion(PresentationResponse walletResponse) {
        String redirectUri = walletResponse.redirectUri();

        boolean sseNavigated = false;
        try {
            page.waitForURL(this::isPostLoginUrl, new Page.WaitForURLOptions().setTimeout(10000));
            sseNavigated = true;
            LOG.info("[Test] SSE navigated browser to: {}", page.url());
        } catch (Exception ignored) {
            LOG.info("[Test] SSE did not navigate within timeout, falling back to manual redirect");
        }

        if (!sseNavigated && redirectUri != null) {
            LOG.info("[Test] Navigating to redirect_uri: {}", redirectUri);
            page.navigate(redirectUri);
            page.waitForLoadState(LoadState.NETWORKIDLE);
        }

        try {
            page.waitForURL(this::isPostLoginUrl, new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = safeGetBodyText();
            throw new AssertionError(
                    "Unexpected state after wallet login. URL: " + page.url() + "\nWallet response: "
                            + walletResponse.rawBody() + "\nRedirect URI: " + redirectUri + "\nPage content: "
                            + bodyText,
                    e);
        }
    }

    void completeFirstBrokerLoginIfNeeded(String usernamePrefix) {
        if (page.locator("input[name='username']").count() == 0) {
            return;
        }

        String uniqueUsername = usernamePrefix + "-" + System.currentTimeMillis();

        page.waitForLoadState(LoadState.NETWORKIDLE);
        fillIfEmpty("username", uniqueUsername);
        fillIfEmpty("email", uniqueUsername + "@example.com");
        fillIfEmpty("firstName", "Test");
        fillIfEmpty("lastName", "User");

        page.locator("input[type='submit'], button[type='submit']").first().click();
        try {
            page.waitForURL(url -> url.startsWith(callbackUrl), new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            String bodyText = safeGetBodyText();
            throw new AssertionError(
                    "First broker login form did not redirect to callback. URL: " + page.url() + "\nPage content: "
                            + bodyText,
                    e);
        }
    }

    void assertLoginSucceeded() {
        assertThat(page.url()).as("Should arrive at callback with auth code").contains("code=");
    }

    void clearBrowserSession() {
        context.clearCookies();
        try {
            page.navigate(kcHostUrl + "/realms/" + realm + "/", new Page.NavigateOptions().setTimeout(10000));
        } catch (Exception e) {
            LOG.warn("Initial navigation failed: {}", e.getMessage());
            try {
                page.navigate("about:blank");
            } catch (Exception ignored) {
            }
        }
        try {
            page.evaluate("() => { window.localStorage.clear(); window.sessionStorage.clear(); }");
        } catch (Exception ignored) {
        }
        context.clearCookies();
    }

    URI buildAuthRequestUri() {
        String state = "s-" + System.nanoTime();
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String codeChallenge;
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String uri = kcHostUrl + "/realms/" + realm + "/protocol/openid-connect/auth" + "?client_id=wallet-mock"
                + "&redirect_uri=" + urlEncode(callbackUrl)
                + "&response_type=code"
                + "&scope=openid"
                + "&state=" + urlEncode(state)
                + "&code_challenge=" + urlEncode(codeChallenge)
                + "&code_challenge_method=S256";
        return URI.create(uri);
    }

    static String extractRequestUri(String walletUrl) {
        String query = walletUrl.contains("?") ? walletUrl.substring(walletUrl.indexOf('?') + 1) : walletUrl;
        for (String param : query.split("&")) {
            if (param.startsWith("request_uri=")) {
                return URLDecoder.decode(param.substring("request_uri=".length()), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalArgumentException("No request_uri found in wallet URL: " + walletUrl);
    }

    static String extractRequestHandleFromRequestUri(String requestUri) {
        String path = URI.create(requestUri).getPath();
        int slash = path.lastIndexOf('/');
        if (slash < 0 || slash + 1 >= path.length()) {
            throw new IllegalArgumentException("No request handle found in request_uri: " + requestUri);
        }
        return path.substring(slash + 1);
    }

    @SuppressWarnings("unchecked")
    static String extractEncryptionKid(String jwt) throws Exception {
        SignedJWT signedJwt = SignedJWT.parse(jwt);
        Map<String, Object> claims = signedJwt.getJWTClaimsSet().getClaims();
        Map<String, Object> clientMetadata = (Map<String, Object>) claims.get("client_metadata");
        if (clientMetadata == null) return null;
        Map<String, Object> jwks = (Map<String, Object>) clientMetadata.get("jwks");
        if (jwks == null) return null;
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        if (keys == null || keys.isEmpty()) return null;
        return (String) keys.get(0).get("kid");
    }

    static String extractRequestClaim(String jwt, String claimName) throws Exception {
        SignedJWT signedJwt = SignedJWT.parse(jwt);
        Object value = signedJwt.getJWTClaimsSet().getClaim(claimName);
        return value != null ? String.valueOf(value) : null;
    }

    boolean isCallbackUrl(String url) {
        return url.startsWith(callbackUrl);
    }

    private boolean isPostLoginUrl(String url) {
        return url.startsWith(callbackUrl)
                || url.contains("/first-broker-login")
                || url.contains("/login-actions/")
                || url.contains("/complete-auth")
                || page.locator("input[name='username']").count() > 0;
    }

    private String convertToOpenid4vpUri(String walletUrl) {
        if (walletUrl.startsWith("openid4vp://")) {
            return walletUrl;
        }
        return walletUrl.replace(wallet.getAuthorizeUrl() + "?", "openid4vp://authorize?");
    }

    private void fillIfEmpty(String fieldName, String value) {
        Locator field = page.locator("input[name='" + fieldName + "']");
        if (field.count() > 0 && field.first().inputValue().isEmpty()) {
            field.first().fill(value);
        }
    }

    private String safeGetBodyText() {
        try {
            String text = page.locator("body").textContent();
            return text.substring(0, Math.min(1000, text.length()));
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
