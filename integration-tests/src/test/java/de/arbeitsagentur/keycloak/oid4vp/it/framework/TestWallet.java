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

import io.github.dominikschlosser.eudi.Credential;
import io.github.dominikschlosser.eudi.EudiWalletContainer;
import io.github.dominikschlosser.eudi.PresentationResponse;
import io.github.dominikschlosser.eudi.TrustListIndexEntry;
import io.github.dominikschlosser.eudi.WalletClient;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An eudi-dev wallet managed by the test framework. It runs in a Docker container with fixed port
 * bindings and advertises {@code localhost} URLs, which resolve from the test JVM, from the
 * embedded Keycloak server and from inside the wallet container alike.
 */
public final class TestWallet implements AutoCloseable {

    public static final String PID_PROVIDERS_LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";

    private final EudiWalletContainer container;
    private final String baseUrl;
    // Every reset restores these, so a test that deletes or replaces credentials cannot leak that
    // change into later tests.
    private final List<String> seededCredentials;

    TestWallet(EudiWalletContainer container, String baseUrl) {
        this.container = container;
        this.baseUrl = baseUrl;
        this.seededCredentials = container.client().getCredentials().stream()
                .map(Credential::raw)
                .toList();
    }

    public EudiWalletContainer container() {
        return container;
    }

    public WalletClient client() {
        return container.client();
    }

    public String baseUrl() {
        return baseUrl;
    }

    public String getAuthorizeUrl() {
        return baseUrl + "/authorize";
    }

    public PresentationResponse acceptPresentationRequest(String uri) {
        return client().acceptPresentationRequest(uri);
    }

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

    public void resetState() {
        client().clearPreferredFormat();
        client().clearNextError();
        restoreSeededCredentials();
    }

    private void restoreSeededCredentials() {
        Set<String> current =
                client().getCredentials().stream().map(Credential::raw).collect(Collectors.toSet());
        if (current.equals(Set.copyOf(seededCredentials))) {
            return;
        }
        client().deleteAllCredentials();
        seededCredentials.forEach(client()::importCredential);
    }

    @Override
    public void close() {
        container.stop();
    }
}
