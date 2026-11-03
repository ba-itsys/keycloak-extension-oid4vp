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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

final class InMemoryAuthenticationSession implements AuthenticationSessionModel {

    final Map<String, String> authNotes = new HashMap<>();

    @Override
    public String getAuthNote(String name) {
        return authNotes.get(name);
    }

    @Override
    public void setAuthNote(String name, String value) {
        authNotes.put(name, value);
    }

    @Override
    public void removeAuthNote(String name) {
        authNotes.remove(name);
    }

    @Override
    public void clearAuthNotes() {
        authNotes.clear();
    }

    @Override
    public String getTabId() {
        throw new UnsupportedOperationException();
    }

    @Override
    public RootAuthenticationSessionModel getParentSession() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, ExecutionStatus> getExecutionStatus() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setExecutionStatus(String authenticator, ExecutionStatus status) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clearExecutionStatus() {
        throw new UnsupportedOperationException();
    }

    @Override
    public UserModel getAuthenticatedUser() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setAuthenticatedUser(UserModel user) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> getRequiredActions() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addRequiredAction(String action) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeRequiredAction(String action) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addRequiredAction(UserModel.RequiredAction action) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeRequiredAction(UserModel.RequiredAction action) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setUserSessionNote(String name, String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, String> getUserSessionNotes() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clearUserSessionNotes() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getClientNote(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setClientNote(String name, String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeClientNote(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, String> getClientNotes() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clearClientNotes() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> getClientScopes() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setClientScopes(Set<String> clientScopes) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getRedirectUri() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setRedirectUri(String uri) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RealmModel getRealm() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ClientModel getClient() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAction() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setAction(String action) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getProtocol() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setProtocol(String method) {
        throw new UnsupportedOperationException();
    }
}
