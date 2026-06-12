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

import com.microsoft.playwright.Browser;
import java.util.List;
import java.util.Map;
import org.keycloak.testframework.TestFrameworkExtension;
import org.keycloak.testframework.injection.Supplier;

/**
 * Test framework extension providing the OID4VP test environment: oid4vc-dev test wallets, a
 * Playwright browser and the OAuth client application under test.
 */
public class Oid4vpTestFrameworkExtension implements TestFrameworkExtension {

    @Override
    public List<Supplier<?, ?>> suppliers() {
        return List.of(new TestWalletSupplier(), new TestAppSupplier(), new PlaywrightBrowserSupplier());
    }

    @Override
    public Map<Class<?>, String> valueTypeAliases() {
        return Map.of(
                TestWallet.class, "wallet",
                TestApp.class, "test-app",
                Browser.class, "playwright-browser");
    }
}
