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
package de.arbeitsagentur.keycloak.oid4vp.domain;

/**
 * The message bundle keys of the texts an End-User sees. The texts live in
 * {@code theme-resources/messages/messages_en.properties}. A deployment can translate and
 * override them there.
 */
public final class Oid4vpMessages {

    public static final String PRESENTATION_REJECTED = "oid4vpPresentationRejected";

    /** Verification broke on the verifier's side, so nothing was decided about the credential. */
    public static final String VERIFICATION_FAILED = "oid4vpVerificationFailed";

    /** The login the browser returns to is over, for example because the page was reloaded. */
    public static final String LOGIN_ENDED = "oid4vpLoginEnded";

    public static final String LOGIN_EXPIRED = "oid4vpLoginExpired";

    /** The browser arrived without the parameters that identify its login. */
    public static final String INVALID_LOGIN_RESPONSE = "oid4vpInvalidLoginResponse";

    public static final String BROWSER_SESSION_MISMATCH = "oid4vpBrowserSessionMismatch";

    /** The deferred identity of the login is gone, so the login cannot be completed. */
    public static final String LOGIN_DATA_MISSING = "oid4vpLoginDataMissing";

    /** No flow is offered at the level of authentication the client requested. */
    public static final String NOT_AVAILABLE_FOR_REQUESTED_LEVEL = "oid4vpNotAvailableForRequestedLevel";

    private Oid4vpMessages() {}
}
