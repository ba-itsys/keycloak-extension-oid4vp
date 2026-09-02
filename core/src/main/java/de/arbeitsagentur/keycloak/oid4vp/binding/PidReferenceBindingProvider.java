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
package de.arbeitsagentur.keycloak.oid4vp.binding;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimPath;
import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimSelection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;

/**
 * Binds an issued credential to the person a PID names, by the claims that identify them. Claims are
 * read the way the OID4VP mappers read them, so a path in dot notation resolves against the claims of
 * an SD-JWT credential and against the namespace of an mDoc, and means here what it means in a mapper
 * and in the principal attribute.
 */
public class PidReferenceBindingProvider implements ReferenceCredentialBindingProvider {

    private static final Logger LOG = Logger.getLogger(PidReferenceBindingProvider.class);

    private final Set<String> credentialTypes;
    private final List<String> claimPaths;

    public PidReferenceBindingProvider(Set<String> credentialTypes, List<String> claimPaths) {
        this.credentialTypes = credentialTypes;
        this.claimPaths = claimPaths;
    }

    @Override
    public Map<String, BoundCredential> bindingMaterial(PresentedCredentials credentials, String subjectCredentialId) {
        if (credentials == null) {
            return Map.of();
        }
        Map<String, BoundCredential> material = new LinkedHashMap<>();
        credentials.byCredentialId().forEach((credentialId, credential) -> {
            if (credentialId.equals(subjectCredentialId) || !isSelected(credential)) {
                return;
            }
            BoundCredential bound = select(credential);
            if (!bound.isEmpty()) {
                material.put(credentialId, bound);
            }
        });
        return material;
    }

    private boolean isSelected(PresentedCredential credential) {
        return credentialTypes.isEmpty() || credentialTypes.contains(credential.type());
    }

    private BoundCredential select(PresentedCredential credential) {
        JsonNode claimsRoot = ClaimSelection.claimsRoot(credential, null);
        if (claimsRoot == null) {
            return new BoundCredential(credential.type(), Map.of());
        }
        Map<String, Object> selected = new LinkedHashMap<>();
        for (String configuredPath : claimPaths) {
            ClaimPath path = ClaimPath.parse(configuredPath);
            if (path == null) {
                LOG.warnf("OID4VP reference binding: '%s' is not a valid claim path and binds nothing", configuredPath);
                continue;
            }
            List<String> values = ClaimSelection.values(path, claimsRoot);
            if (!values.isEmpty()) {
                selected.put(configuredPath, values.size() == 1 ? values.get(0) : values);
            }
        }
        return new BoundCredential(credential.type(), selected);
    }
}
