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
package de.arbeitsagentur.keycloak.oid4vp.mapper;

import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.AbstractInMemoryUserAdapter;

/** Typed in-memory {@link UserModel} test double for asserting brokered user updates. */
final class InMemoryUser extends AbstractInMemoryUserAdapter {

    InMemoryUser() {
        super(null, null, "test-user");
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        throw new UnsupportedOperationException("Credentials are not part of the mapper tests");
    }
}
