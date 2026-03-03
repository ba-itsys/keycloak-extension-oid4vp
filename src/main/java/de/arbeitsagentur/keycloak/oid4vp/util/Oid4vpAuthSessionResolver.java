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
package de.arbeitsagentur.keycloak.oid4vp.util;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class Oid4vpAuthSessionResolver {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpRequestObjectStore requestObjectStore;

    public Oid4vpAuthSessionResolver(
            KeycloakSession session, RealmModel realm, Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.requestObjectStore = requestObjectStore;
    }

    public AuthenticationSessionModel resolveFromStore(String state, String tabIdHint) {
        if (state == null) return null;

        Oid4vpRequestObjectStore.StateEntry stateEntry = requestObjectStore.resolveByState(session, state);
        if (stateEntry == null || stateEntry.rootSessionId() == null) {
            return null;
        }

        String tabId = tabIdHint;
        if (tabId == null) {
            tabId = stateEntry.tabId();
        }
        if (tabId == null && state.contains(".")) {
            tabId = state.substring(0, state.indexOf('.'));
        }

        return resolveFromTokenEntry(stateEntry.rootSessionId(), tabId);
    }

    public AuthenticationSessionModel resolveFromTokenEntry(String rootSessionId, String tabId) {
        if (rootSessionId == null) return null;

        RootAuthenticationSessionModel rootSession =
                session.authenticationSessions().getRootAuthenticationSession(realm, rootSessionId);
        if (rootSession == null) {
            return null;
        }

        return tabId != null ? rootSession.getAuthenticationSessions().get(tabId) : null;
    }
}
