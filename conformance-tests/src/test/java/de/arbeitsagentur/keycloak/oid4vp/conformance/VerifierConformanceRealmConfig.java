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
package de.arbeitsagentur.keycloak.oid4vp.conformance;

import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;

public class VerifierConformanceRealmConfig implements RealmConfig {

    public static final String REALM = "wallet-demo";
    public static final String CLIENT_ID = "wallet-mock";

    @Override
    public RealmBuilder configure(RealmBuilder realm) {
        return realm.name(REALM)
                .clients(ClientBuilder.create(CLIENT_ID)
                        .publicClient(true)
                        .protocol("openid-connect")
                        .redirectUris("*")
                        .webOrigins("*")
                        .attribute("pkce.code.challenge.method", "S256"));
    }
}
