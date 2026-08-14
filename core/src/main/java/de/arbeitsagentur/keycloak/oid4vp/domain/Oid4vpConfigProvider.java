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
 * Abstraction over OID4VP identity provider configuration settings.
 *
 * <p>Implemented by {@link de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig} and
 * used by services that need configuration without depending on the full Keycloak
 * {@code IdentityProviderModel}. This also allows unit testing with simple stubs.
 */
public interface Oid4vpConfigProvider {

    String getAlias();

    /**
     * Returns whether the verified SD-JWT issuer is allowed.
     *
     * <p>This check currently applies only to credentials that expose a canonical issuer string
     * (for example SD-JWT `iss`). mDoc credentials are not filtered by this allow-list because
     * mDoc does not define a standard canonical credential-issuer string equivalent to SD-JWT
     * `iss`.
     */
    boolean isIssuerAllowed(String issuer);

    /**
     * Dot notation claim path of the claim that becomes the brokered subject. For mDoc
     * presentations the path addresses a data element, resolved against each presented namespace.
     */
    String getPrincipalAttribute();

    /**
     * The credential id the subject is read from, or blank to read it from the first requested
     * credential the wallet presents.
     */
    String getPrincipalCredentialId();

    int getSsePollIntervalMs();

    int getSseTimeoutSeconds();

    int getSsePingIntervalSeconds();

    int getCrossDeviceCompleteTtlSeconds();

    boolean isTransientUsersEnabled();

    int getClockSkewSeconds();
}
