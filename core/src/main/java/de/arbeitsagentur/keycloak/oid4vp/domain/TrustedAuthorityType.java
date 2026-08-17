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
 * Type identifier of a DCQL {@code trusted_authorities} entry.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1 — Trusted Authorities Query</a>
 */
public enum TrustedAuthorityType {

    /** Base64url {@code KeyIdentifier} of an {@code AuthorityKeyIdentifier}, OID4VP 1.0 §6.1.1.1. */
    AKI(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_AKI),

    /**
     * Identifier of an ETSI trusted list, OID4VP 1.0 §6.1.1.2. The specification defines the value
     * as the identifier of a trusted list specified in ETSI TS 119 612. This extension advertises
     * the URL of the ETSI TS 119 602 trust list it verifies against, the trust list of the EUDI
     * ecosystem. The wallet resolves the advertised URL either way, so the entry stays a hint for
     * credential selection rather than a format contract.
     */
    ETSI_TL(Oid4vpConstants.DCQL_TRUSTED_AUTHORITY_ETSI_TL);

    private final String dcqlValue;

    TrustedAuthorityType(String dcqlValue) {
        this.dcqlValue = dcqlValue;
    }

    /** The {@code type} member value of the DCQL entry. */
    public String dcqlValue() {
        return dcqlValue;
    }
}
