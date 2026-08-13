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
import java.util.List;
import java.util.Optional;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trust material identity provider contract of this extension.
 *
 * <p>Extends the upstream JWK and X.509 surfaces with what the OID4VP verifier additionally needs:
 * revocation (status list) trust, directly trusted issuer certificates for pinned or chainless
 * credentials, and the DCQL {@code trusted_authorities} advertisement values. All methods default
 * to empty, matching the upstream style where providers implement only the surfaces they serve.
 */
public interface Oid4vpTrustMaterialIdentityProvider<C extends IdentityProviderModel>
        extends X509TrustMaterialIdentityProvider<C> {

    /**
     * End entity certificates listed as issuance services. Their keys are trusted directly for
     * credentials that carry no certificate chain, and a presented chain whose leaf equals one of
     * these certificates is trusted without further path building.
     */
    default List<X509Certificate> directIssuerCertificates() {
        return List.of();
    }

    /** Certificates of status list (revocation) services. */
    default List<X509Certificate> revocationCertificates() {
        return List.of();
    }

    /**
     * Certificate key identifiers of the issuance anchors, for DCQL {@code trusted_authorities}
     * entries of type {@code aki}.
     */
    default List<String> trustedAuthorityKeyIdentifiers() {
        return List.of();
    }

    /** Trust list URL for DCQL {@code trusted_authorities} entries of type {@code etsi_tl}. */
    default Optional<String> trustListUrl() {
        return Optional.empty();
    }
}
