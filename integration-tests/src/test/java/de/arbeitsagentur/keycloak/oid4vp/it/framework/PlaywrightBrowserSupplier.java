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
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Playwright;
import org.keycloak.testframework.injection.InstanceContext;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.injection.RequestedInstance;
import org.keycloak.testframework.injection.Supplier;

public class PlaywrightBrowserSupplier implements Supplier<Browser, InjectPlaywrightBrowser> {

    private static final String PLAYWRIGHT_NOTE = "playwright";

    @Override
    public Browser getValue(InstanceContext<Browser, InjectPlaywrightBrowser> instanceContext) {
        Playwright playwright = Playwright.create();
        instanceContext.addNote(PLAYWRIGHT_NOTE, playwright);
        return playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
    }

    @Override
    public boolean compatible(
            InstanceContext<Browser, InjectPlaywrightBrowser> a,
            RequestedInstance<Browser, InjectPlaywrightBrowser> b) {
        return true;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public void close(InstanceContext<Browser, InjectPlaywrightBrowser> instanceContext) {
        instanceContext.getValue().close();
        instanceContext.getNote(PLAYWRIGHT_NOTE, Playwright.class).close();
    }
}
