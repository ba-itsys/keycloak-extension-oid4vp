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

import java.util.Objects;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Resolves Keycloak authentication sessions from OID4VP session state.
 *
 * <p>In the OID4VP direct_post flow, the wallet's response arrives in a separate HTTP request
 * without session cookies. This resolver recovers the original authentication session using
 * the state parameter (via {@link Oid4vpRequestObjectStore}) or root session ID stored during
 * request object generation.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Response Mode direct_post</a>
 */
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

    /** Resolves an authentication session using the OAuth {@code state} parameter from the store. */
    public AuthenticationSessionModel resolveFromStore(String state, String tabIdHint) {
        if (state == null) return null;

        Oid4vpRequestObjectStore.RequestContextEntry requestContext = requestObjectStore.resolveByState(session, state);
        if (requestContext == null || requestContext.rootSessionId() == null) {
            return null;
        }

        String tabId = tabIdHint;
        if (tabId == null) {
            tabId = requestContext.tabId();
        }
        if (tabId == null && state.contains(".")) {
            tabId = state.substring(0, state.indexOf('.'));
        }

        return resolveFromTokenEntry(requestContext.rootSessionId(), tabId);
    }

    /** Resolves an authentication session directly from a stored request context. */
    public AuthenticationSessionModel resolveFromRequestContext(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        if (requestContext == null) {
            return null;
        }
        return resolveFromTokenEntry(requestContext.rootSessionId(), requestContext.tabId());
    }

    /** Resolves an authentication session directly from root session and tab IDs. */
    public AuthenticationSessionModel resolveFromTokenEntry(String rootSessionId, String tabId) {
        if (rootSessionId == null) return null;

        RootAuthenticationSessionModel rootSession =
                session.authenticationSessions().getRootAuthenticationSession(realm, rootSessionId);
        if (rootSession == null) {
            return null;
        }

        return tabId != null ? rootSession.getAuthenticationSessions().get(tabId) : null;
    }

    /**
     * Resolves the current browser authentication session for the same client/tab as the expected
     * session. First trusts an already-populated request context auth session, then falls back to
     * Keycloak's auth-session cookie handling.
     */
    public AuthenticationSessionModel resolveCurrentBrowserSession(AuthenticationSessionModel expectedAuthSession) {
        if (expectedAuthSession == null) {
            return null;
        }

        AuthenticationSessionModel current = session.getContext().getAuthenticationSession();
        if (sameAuthenticationSession(current, expectedAuthSession)) {
            return current;
        }

        ClientModel client = expectedAuthSession.getClient();
        String tabId = expectedAuthSession.getTabId();
        if (client == null || tabId == null) {
            return null;
        }

        try {
            return new AuthenticationSessionManager(session).getCurrentAuthenticationSession(realm, client, tabId);
        } catch (RuntimeException e) {
            return null;
        }
    }

    public boolean sameAuthenticationSession(AuthenticationSessionModel first, AuthenticationSessionModel second) {
        if (first == null || second == null) {
            return false;
        }

        String firstRootSessionId =
                first.getParentSession() != null ? first.getParentSession().getId() : null;
        String secondRootSessionId =
                second.getParentSession() != null ? second.getParentSession().getId() : null;
        String firstClientId = first.getClient() != null ? first.getClient().getId() : null;
        String secondClientId = second.getClient() != null ? second.getClient().getId() : null;

        return Objects.equals(firstRootSessionId, secondRootSessionId)
                && Objects.equals(first.getTabId(), second.getTabId())
                && Objects.equals(firstClientId, secondClientId);
    }
}
