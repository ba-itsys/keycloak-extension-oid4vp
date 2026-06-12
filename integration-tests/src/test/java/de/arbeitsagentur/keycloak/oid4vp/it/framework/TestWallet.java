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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import io.github.dominikschlosser.oid4vc.TrustListIndexEntry;
import io.github.dominikschlosser.oid4vc.WalletClient;
import java.net.URI;

/**
 * An oid4vc-dev wallet managed by the test framework. The wallet runs in a Docker container with
 * fixed port bindings and advertises {@code localhost} URLs that resolve both from the test JVM
 * (including the embedded Keycloak server) and from within the wallet container itself.
 */
public final class TestWallet implements AutoCloseable {

    public static final String PID_PROVIDERS_LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";

    private final Oid4vcContainer container;
    private final String baseUrl;

    TestWallet(Oid4vcContainer container, String baseUrl) {
        this.container = container;
        this.baseUrl = baseUrl;
    }

    public Oid4vcContainer container() {
        return container;
    }

    public WalletClient client() {
        return container.client();
    }

    // Base URL the wallet advertises, reachable from the test JVM and the Keycloak server
    public String baseUrl() {
        return baseUrl;
    }

    public String getAuthorizeUrl() {
        return baseUrl + "/authorize";
    }

    public PresentationResponse acceptPresentationRequest(String uri) {
        return client().acceptPresentationRequest(uri);
    }

    // Trust list URL of the EU PID providers list
    public String pidTrustListUrl() {
        return trustListUrl(PID_PROVIDERS_LOTE_TYPE);
    }

    public String trustListUrl(String loTEType) {
        TrustListIndexEntry trustList = client().getTrustLists().stream()
                .filter(entry -> loTEType.equals(entry.loteType()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No trust list found for LoTE type " + loTEType));
        String path = trustList.path();
        if (path != null && !path.isBlank()) {
            return URI.create(baseUrl).resolve(path).toString();
        }
        return baseUrl + "/api/trustlists/" + trustList.id();
    }

    // Resets per-test wallet state such as preferred formats and scripted errors
    public void resetState() {
        client().clearPreferredFormat();
        client().clearNextError();
    }

    @Override
    public void close() {
        container.stop();
    }
}
