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

import java.security.cert.X509Certificate;
import org.keycloak.utils.StringUtil;

/**
 * Binds a directly trusted certificate to the issuer it is trusted for, so a certificate published
 * for one issuer must not verify a credential that claims to come from another. A null issuer means
 * the provider does not identify one, and the certificate is then trusted for any issuer.
 */
public record TrustedIssuerCertificate(String issuer, X509Certificate certificate) {

    /**
     * Trusts a certificate for any issuer. A trust list names services and no SD-JWT issuer
     * identifiers, so its end entity certificates arrive this way.
     */
    public static TrustedIssuerCertificate ofAnyIssuer(X509Certificate certificate) {
        return new TrustedIssuerCertificate(null, certificate);
    }

    public boolean trustedFor(String credentialIssuer) {
        return StringUtil.isBlank(issuer) || issuer.equals(credentialIssuer);
    }
}
