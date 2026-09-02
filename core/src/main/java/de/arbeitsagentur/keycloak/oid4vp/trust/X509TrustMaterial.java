/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Set;

/**
 * X.509 trust material and validation policy exposed by a trust material identity provider.
 *
 * <p>Mirror of {@code org.keycloak.broker.provider.X509TrustMaterial} from Keycloak main. Delete
 * this copy and switch imports once the extension builds against a Keycloak release that ships it.
 * It deviates from upstream in that anchors must be CA certificates but need not be self-issued
 * roots, because ETSI trust lists commonly list the issuing (intermediate) CA of a trust domain.
 *
 * @param trustAnchors              CA certificates anchoring one trust domain
 * @param requiredExtendedKeyUsages extended key usage OIDs. The end entity certificate must contain
 *                                  at least one of them, and an empty list imposes no restriction.
 */
public record X509TrustMaterial(Set<X509Certificate> trustAnchors, List<String> requiredExtendedKeyUsages) {

    public X509TrustMaterial {
        trustAnchors = Set.copyOf(trustAnchors);
        requiredExtendedKeyUsages = List.copyOf(requiredExtendedKeyUsages);
        if (trustAnchors.isEmpty()) {
            throw new IllegalArgumentException("At least one X.509 trust anchor is required");
        }
        trustAnchors.forEach(X509TrustMaterial::validateTrustAnchor);
    }

    private static void validateTrustAnchor(X509Certificate certificate) {
        if (certificate.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("X.509 trust anchors must be CA certificates");
        }

        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            throw new IllegalArgumentException("X.509 trust anchors must be valid for certificate signing");
        }
    }
}
