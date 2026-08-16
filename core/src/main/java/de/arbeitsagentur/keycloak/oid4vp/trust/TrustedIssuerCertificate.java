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
 * A directly trusted issuer certificate together with the issuer it is trusted for. The counterpart
 * of {@link TrustedIssuerKey} for the credentials that pin a certificate instead of naming a key,
 * and it keeps trust domains apart the same way: a certificate published for one issuer must not
 * verify a credential that claims to come from another.
 *
 * @param issuer the credential {@code iss} this certificate is trusted for, or null when the
 *               provider does not identify an issuer and the certificate is trusted for any of them
 * @param certificate the trusted certificate
 */
public record TrustedIssuerCertificate(String issuer, X509Certificate certificate) {

    /**
     * A certificate trusted for any issuer, as exposed by providers that do not know whose it is. A
     * trust list names services rather than SD-JWT issuer identifiers, so its end entity
     * certificates arrive this way.
     */
    public static TrustedIssuerCertificate ofAnyIssuer(X509Certificate certificate) {
        return new TrustedIssuerCertificate(null, certificate);
    }

    /** Whether this certificate may verify a credential issued by the given issuer. */
    public boolean trustedFor(String credentialIssuer) {
        return StringUtil.isBlank(issuer) || issuer.equals(credentialIssuer);
    }
}
