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
package de.arbeitsagentur.keycloak.oid4vp.event;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Sends the events to Keycloak's event system, so the event listeners enabled in the realm and the
 * event store receive them. Keycloak keeps a failing event listener from affecting the login.
 */
public final class Oid4vpEventService {

    private static final String STATE_ATTRIBUTE = "oid4vp.event.state";

    private Oid4vpEventService() {}

    public static void fire(KeycloakSession session, Oid4vpEvent event) {
        if (session == null || event.realmId() == null) {
            return;
        }
        RealmModel realm = session.realms().getRealm(event.realmId());
        if (realm == null) {
            return;
        }
        KeycloakEventMapping mapped = KeycloakEventMapping.of(event);
        EventBuilder builder =
                new EventBuilder(realm, session, session.getContext().getConnection());
        builder.event(mapped.type());
        mapped.details().forEach(builder::detail);
        if (mapped.clientId() != null) {
            builder.client(mapped.clientId());
        }
        if (mapped.userId() != null) {
            builder.user(mapped.userId());
        }
        if (mapped.error() != null) {
            builder.error(mapped.error());
        } else {
            builder.success();
        }
    }

    // Fires the event once per session and key, for a check that runs several times per request.
    public static void fireOnce(KeycloakSession session, String key, Oid4vpEvent event) {
        if (session == null || session.getAttribute(key) != null) {
            return;
        }
        session.setAttribute(key, Boolean.TRUE);
        fire(session, event);
    }

    // Marks the session as answering this login, so that the events it fires can name the state.
    public static void bindState(KeycloakSession session, String state) {
        session.setAttribute(STATE_ATTRIBUTE, state);
    }

    public static String state(KeycloakSession session) {
        return session != null ? session.getAttribute(STATE_ATTRIBUTE, String.class) : null;
    }

    public static String realmId(KeycloakSession session) {
        RealmModel realm = session != null ? session.getContext().getRealm() : null;
        return realm != null ? realm.getId() : null;
    }
}
