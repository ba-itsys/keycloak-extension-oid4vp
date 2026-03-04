/*
 * Copyright 2025 Bundesagentur für Arbeit
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
package de.arbeitsagentur.keycloak.oid4vp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * JUnit extension that tracks IdP config changes and restores them after each test.
 *
 * <p>Usage:
 * <pre>
 * &#64;RegisterExtension
 * IdpConfigScope idpConfig = new IdpConfigScope(() -> adminClient, REALM);
 *
 * &#64;Test void myTest() throws Exception {
 *     idpConfig.set(X509_CERTIFICATE_PEM, certPem);
 *     idpConfig.set(CLIENT_ID_SCHEME, "x509_san_dns");
 *     idpConfig.apply();
 *     // ... test ...
 *     // cleanup is automatic
 * }
 * </pre>
 */
class IdpConfigScope implements AfterEachCallback {

    private final Supplier<KeycloakAdminClient> adminSupplier;
    private final String realm;
    private final Map<String, String> pending = new LinkedHashMap<>();
    private final Map<String, String> originals = new LinkedHashMap<>();

    IdpConfigScope(Supplier<KeycloakAdminClient> adminSupplier, String realm) {
        this.adminSupplier = adminSupplier;
        this.realm = realm;
    }

    /** Buffer a config change. Call {@link #apply()} to send all buffered changes in one request. */
    IdpConfigScope set(String key, String value) {
        pending.put(key, value);
        return this;
    }

    /** Send all buffered changes to Keycloak in a single admin API PUT. */
    @SuppressWarnings("unchecked")
    void apply() throws Exception {
        if (pending.isEmpty()) {
            return;
        }
        KeycloakAdminClient admin = adminSupplier.get();
        Map<String, Object> idp = admin.getJson("/admin/realms/" + realm + "/identity-provider/instances/oid4vp");
        Map<String, String> config = (Map<String, String>) idp.get("config");
        for (String key : pending.keySet()) {
            if (!originals.containsKey(key)) {
                originals.put(key, config.getOrDefault(key, ""));
            }
        }
        Oid4vpTestKeycloakSetup.setIdpConfigs(admin, realm, pending);
        pending.clear();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        pending.clear();
        if (originals.isEmpty()) {
            return;
        }
        Oid4vpTestKeycloakSetup.setIdpConfigs(adminSupplier.get(), realm, originals);
        originals.clear();
    }
}
