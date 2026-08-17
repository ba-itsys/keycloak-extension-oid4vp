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
package de.arbeitsagentur.keycloak.oid4vp.util;

import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

/**
 * Fingerprints of certificates, used to key caches by the trust material a cached document was
 * verified against. Two sets of trust material that differ produce different keys, so a document
 * cached for one of them is never served for the other.
 */
public final class CertificateFingerprints {

    private CertificateFingerprints() {}

    /** The SHA-256 fingerprints of the given certificates, sorted so their order does not matter. */
    public static List<String> of(List<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return List.of();
        }
        return certificates.stream()
                .map(CertificateFingerprints::fingerprint)
                .sorted()
                .toList();
    }

    private static String fingerprint(X509Certificate certificate) {
        try {
            return Base64Url.encode(HashUtils.hash(JavaAlgorithm.SHA256, certificate.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint certificate", e);
        }
    }
}
