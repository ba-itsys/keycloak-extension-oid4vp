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

import java.util.List;

/**
 * The OID4VP identity provider configuration as the services read it. They depend on this
 * interface instead of the Keycloak {@code IdentityProviderModel}, which keeps them testable with
 * simple stubs.
 */
public interface Oid4vpConfigProvider {

    String getAlias();

    /**
     * Returns whether the verified issuer is on the allow list. Only credentials that expose a
     * canonical issuer string such as the SD-JWT {@code iss} are filtered this way, so mDoc
     * credentials pass, because mDoc defines no equivalent.
     */
    boolean isIssuerAllowed(String issuer);

    /**
     * Returns the credentials the subject may be read from, each with the claim that carries it,
     * in the order they are tried. Nothing else in the configuration says which claim identifies
     * the user, so the list is empty only when the subject comes from a transient user.
     */
    List<PrincipalAttribute> getPrincipalAttributes();

    int getSsePollIntervalMs();

    int getSseTimeoutSeconds();

    int getSsePingIntervalSeconds();

    int getCrossDeviceCompleteTtlSeconds();

    /**
     * Returns whether a presentation without the subject credential is expected. The verifier then
     * generates a pseudonymous subject instead of failing the login.
     */
    boolean isAllowMissingSubjectCredential();

    boolean isTransientUsersEnabled();

    int getClockSkewSeconds();
}
