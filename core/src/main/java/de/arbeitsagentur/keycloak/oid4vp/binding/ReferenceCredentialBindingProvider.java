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
package de.arbeitsagentur.keycloak.oid4vp.binding;

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.util.Map;
import org.keycloak.provider.Provider;

/**
 * Selects what a credential this Keycloak issues is bound to, out of the presentation it is issued for.
 * The same selection has to be made when the credential is issued and when it is presented again, and
 * the code on both sides cannot share configuration. That is why this is a provider both sides resolve
 * instead of a setting each of them reads.
 */
public interface ReferenceCredentialBindingProvider extends Provider {

    /**
     * Selects what this presentation is bound by, keyed by credential id. An empty result binds the
     * credential to nothing, so it is then accepted in any presentation. The subject credential binds to
     * the others and is never part of the material itself.
     */
    Map<String, BoundCredential> bindingMaterial(PresentedCredentials credentials, String subjectCredentialId);

    @Override
    default void close() {}
}
