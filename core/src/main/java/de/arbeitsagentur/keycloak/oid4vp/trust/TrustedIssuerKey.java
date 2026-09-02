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
package de.arbeitsagentur.keycloak.oid4vp.trust;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.utils.StringUtil;

/**
 * A trusted issuer key together with the issuer it is trusted for. Binding the key to an issuer
 * keeps trust domains apart, so a key published by one issuer must not verify a credential that
 * claims to come from another.
 *
 * @param issuer the credential {@code iss} this key is trusted for. Null when the provider does not
 *               identify an issuer. The key is then trusted for any issuer.
 */
public record TrustedIssuerKey(String issuer, JWK jwk) {

    /** Returns a key trusted for any issuer, as exposed by providers that only implement the upstream contract. */
    public static TrustedIssuerKey ofAnyIssuer(JWK jwk) {
        return new TrustedIssuerKey(null, jwk);
    }

    /** Returns whether this key may verify a credential issued by the given issuer. */
    public boolean trustedFor(String credentialIssuer) {
        return StringUtil.isBlank(issuer) || issuer.equals(credentialIssuer);
    }

    /**
     * Returns whether this key answers the given JOSE {@code kid}. A key without an id answers every
     * kid, and a credential without a kid is answered by every key.
     */
    public boolean matchesKeyId(String keyId) {
        String ownKeyId = jwk != null ? jwk.getKeyId() : null;
        return StringUtil.isBlank(keyId) || StringUtil.isBlank(ownKeyId) || ownKeyId.equals(keyId);
    }
}
