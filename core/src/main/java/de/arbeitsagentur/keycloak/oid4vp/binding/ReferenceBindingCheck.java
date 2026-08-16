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
 * Whether a credential offered as the subject of a login was issued for a presentation like this
 * one.
 *
 * <p>Not a variation point. The identity provider always wires {@link
 * ReferenceCredentialBinding#checkOf}, and what a deployment does choose is the {@link
 * ReferenceCredentialBindingProvider} behind it, which selects the claims. This exists so the
 * verifier can ask for an answer that needs the realm keys without holding a session of its own.
 */
public interface ReferenceBindingCheck {

    /**
     * Whether the subject credential was issued for a presentation like this one. A credential
     * carrying no reference credential binding is accepted in any presentation.
     */
    boolean boundToPresentation(PresentedCredentials credentials, String subjectCredentialId, String claimedBinding);

    /**
     * Whether the presentation carries other credentials a reference credential binding would cover.
     * A subject credential this realm issues alongside such credentials is always bound to them, so a
     * subject credential presented next to them yet carrying no binding claim has had that binding
     * withheld and must not be accepted as the subject.
     */
    boolean bindsToOtherCredentials(PresentedCredentials credentials, String subjectCredentialId);
}
