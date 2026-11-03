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
 * Binds a trusted key to the issuer it is trusted for, so a key published by one issuer must not
 * verify a credential that claims to come from another. A null issuer means the provider does not
 * identify one, and the key is then trusted for any issuer.
 */
public record TrustedIssuerKey(String issuer, JWK jwk) {

    // Trusts a key for any issuer, because the upstream contract binds no issuer to its keys.
    public static TrustedIssuerKey ofAnyIssuer(JWK jwk) {
        return new TrustedIssuerKey(null, jwk);
    }

    public boolean trustedFor(String credentialIssuer) {
        return StringUtil.isBlank(issuer) || issuer.equals(credentialIssuer);
    }

    public boolean matchesKeyId(String keyId) {
        String ownKeyId = jwk != null ? jwk.getKeyId() : null;
        return StringUtil.isBlank(keyId) || StringUtil.isBlank(ownKeyId) || ownKeyId.equals(keyId);
    }
}
