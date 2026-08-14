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

/**
 * Wallet that asks for a credential as the OID4VCI client the credential offer is addressed to.
 * Keycloak resolves the offer against that client, so both sides have to name the same one.
 */
public class VciTestWalletConfig implements TestWalletConfig {

    public static final String VCI_CLIENT_ID = "wallet-vci";

    @Override
    public TestWalletConfigBuilder configure(TestWalletConfigBuilder wallet) {
        return wallet.customize(container -> container.withVciClientId(VCI_CLIENT_ID));
    }
}
