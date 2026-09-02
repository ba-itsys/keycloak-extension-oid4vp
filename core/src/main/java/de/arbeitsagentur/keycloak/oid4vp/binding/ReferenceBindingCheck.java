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

/**
 * Whether a credential offered as the subject of a login was issued for a presentation like this one.
 * The identity provider always wires {@link ReferenceCredentialBinding#checkOf}, so this interface is
 * not a variation point. It exists so the verifier can ask for an answer that needs the realm keys
 * without holding a session of its own.
 */
public interface ReferenceBindingCheck {

    /**
     * Reports whether the subject credential was issued for a presentation like this one. A credential
     * that carries no reference credential binding is accepted in any presentation.
     */
    boolean boundToPresentation(PresentedCredentials credentials, String subjectCredentialId, String claimedBinding);

    /**
     * Reports whether the presentation carries other credentials a reference credential binding would
     * cover. A subject credential this realm issues alongside such credentials is always bound to them,
     * so one presented next to them without a binding claim has had that binding withheld and must not
     * be accepted as the subject.
     */
    boolean bindsToOtherCredentials(PresentedCredentials credentials, String subjectCredentialId);
}
