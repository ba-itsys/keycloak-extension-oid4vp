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

import java.util.List;
import java.util.stream.Stream;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trust material identity providers that additionally expose X.509 trust anchors and policy.
 *
 * <p>Mirror of the X.509 default methods that Keycloak main adds to
 * {@code org.keycloak.broker.provider.TrustMaterialIdentityProvider}. Keycloak 26.7 only ships the
 * {@code resolveKeys} method on that interface. Delete this sub-interface and implement the
 * upstream interface directly once the extension builds against a Keycloak release that ships the
 * X.509 methods.
 */
public interface X509TrustMaterialIdentityProvider<C extends IdentityProviderModel>
        extends TrustMaterialIdentityProvider<C> {

    /**
     * Resolves X.509 trust anchors and policy. Providers that only expose JWKs do not need to implement this method.
     */
    default Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
        return Stream.empty();
    }

    /**
     * Validates the x5c certificate chain of a presented artifact against this provider's X.509
     * trust material and returns the chain leaf key. Exposing X.509 trust anchors mandates chain
     * validation: a missing or unverifiable chain fails.
     *
     * @return the leaf key of the validated chain, or null when this provider exposes no X.509
     *         trust material
     */
    default JWK validateX509Chain(TrustMaterialRequest request, List<String> x5c, String algorithm)
            throws VerificationException {
        List<X509TrustMaterial> trustMaterials = resolveX509Trust(request).toList();
        if (trustMaterials.isEmpty()) {
            return null;
        }
        if (x5c == null || x5c.isEmpty()) {
            throw new VerificationException(
                    "The configured X.509 trust anchors mandate certificate chain validation, but no x5c "
                            + "certificate chain was presented");
        }
        return validateX509Chain(trustMaterials, x5c, algorithm);
    }

    /**
     * Validates the x5c certificate chain against the given trust materials and returns the chain
     * leaf key. The materials are tried in order and the first successful validation wins.
     *
     * @return the leaf key of the validated chain, or null if no trust material was given
     */
    static JWK validateX509Chain(List<X509TrustMaterial> trustMaterials, List<String> x5c, String algorithm)
            throws VerificationException {
        VerificationException lastFailure = null;
        for (X509TrustMaterial trustMaterial : trustMaterials) {
            try {
                return X509CertificateChainValidator.validate(
                        x5c, algorithm, trustMaterial.trustAnchors(), trustMaterial.requiredExtendedKeyUsages());
            } catch (VerificationException e) {
                lastFailure = e;
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        return null;
    }
}
