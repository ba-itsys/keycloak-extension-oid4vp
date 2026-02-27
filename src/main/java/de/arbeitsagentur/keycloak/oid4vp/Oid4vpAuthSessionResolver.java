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
package de.arbeitsagentur.keycloak.oid4vp;

import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class Oid4vpAuthSessionResolver {

    private static final Logger LOG = Logger.getLogger(Oid4vpAuthSessionResolver.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final Oid4vpRequestObjectStore requestObjectStore;

    public Oid4vpAuthSessionResolver(
            KeycloakSession session, RealmModel realm, Oid4vpRequestObjectStore requestObjectStore) {
        this.session = session;
        this.realm = realm;
        this.requestObjectStore = requestObjectStore;
    }

    public AuthenticationSessionModel resolve(
            String state, String tabId, AbstractIdentityProvider.AuthenticationCallback callback) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession != null) {
            return authSession;
        }
        if (StringUtil.isNotBlank(tabId)) {
            try {
                return callback.getAndVerifyAuthenticationSession(state);
            } catch (Exception e) {
                LOG.debugf("Failed to resolve auth session via callback: %s", e.getMessage());
            }
        }
        return null;
    }

    public AuthenticationSessionModel resolveFromStore(String state, String tabIdHint) {
        if (state == null) return null;

        Oid4vpRequestObjectStore.StoredRequestObject stored = requestObjectStore.resolveByState(session, state);
        if (stored == null || stored.rootSessionId() == null) {
            return null;
        }

        RootAuthenticationSessionModel rootSession =
                session.authenticationSessions().getRootAuthenticationSession(realm, stored.rootSessionId());
        if (rootSession == null) {
            return null;
        }

        String tabId = tabIdHint;
        if (tabId == null && state.contains(".")) {
            tabId = state.substring(0, state.indexOf('.'));
        }

        return tabId != null ? findAuthSessionInRoot(rootSession, tabId) : null;
    }

    public AuthenticationSessionModel findAuthSessionInRoot(RootAuthenticationSessionModel rootSession, String tabId) {
        for (Map.Entry<String, AuthenticationSessionModel> entry :
                rootSession.getAuthenticationSessions().entrySet()) {
            if (entry.getKey().equals(tabId)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
