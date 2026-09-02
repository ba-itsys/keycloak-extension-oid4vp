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
 * A directly trusted issuer certificate together with the issuer it is trusted for, the counterpart
 * of {@link TrustedIssuerKey} for credentials that pin a certificate instead of naming a key. It
 * keeps trust domains apart the same way, so a certificate published for one issuer must not verify
 * a credential that claims to come from another.
 *
 * @param issuer the credential {@code iss} this certificate is trusted for. Null when the provider
 *               does not identify an issuer. The certificate is then trusted for any issuer.
 */
public record TrustedIssuerCertificate(String issuer, X509Certificate certificate) {

    /**
     * Returns a certificate trusted for any issuer, as exposed by providers that do not know whose
     * it is. A trust list names services rather than SD-JWT issuer identifiers, so its end entity
     * certificates arrive this way.
     */
    public static TrustedIssuerCertificate ofAnyIssuer(X509Certificate certificate) {
        return new TrustedIssuerCertificate(null, certificate);
    }

    /** Returns whether this certificate may verify a credential issued by the given issuer. */
    public boolean trustedFor(String credentialIssuer) {
        return StringUtil.isBlank(issuer) || issuer.equals(credentialIssuer);
    }
}
