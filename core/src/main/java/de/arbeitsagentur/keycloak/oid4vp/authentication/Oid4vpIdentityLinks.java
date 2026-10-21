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
package de.arbeitsagentur.keycloak.oid4vp.authentication;

import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Finds and stores the user a presentation identifies through the identity provider link, the same
 * link a login through the OID4VP identity provider reads and writes. A user linked here therefore
 * also logs in with the identity provider, and the other way round.
 */
public class Oid4vpIdentityLinks {

    protected final KeycloakSession session;
    protected final RealmModel realm;

    public Oid4vpIdentityLinks(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    public UserModel linkedUser(Oid4vpPresentation presentation) {
        return session.users()
                .getUserByFederatedIdentity(
                        realm,
                        new FederatedIdentityModel(
                                presentation.identityProviderAlias(), presentation.identityKey(), null));
    }

    /**
     * Links the identity key to the user. Keycloak keeps one link per identity provider and user, so
     * an earlier link of the user to the identity provider is replaced.
     */
    public void link(UserModel user, String identityProviderAlias, String identityKey) {
        session.users().removeFederatedIdentity(realm, user, identityProviderAlias);
        session.users()
                .addFederatedIdentity(
                        realm,
                        user,
                        new FederatedIdentityModel(identityProviderAlias, identityKey, user.getUsername()));
    }
}
