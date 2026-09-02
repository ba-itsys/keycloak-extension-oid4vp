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
package de.arbeitsagentur.keycloak.oid4vp.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialId;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentationType;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import java.util.Map;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.util.JsonSerialization;

/** Brokered identity contexts carrying a single presented credential, as the callback builds them. */
final class MapperTestContexts {

    private MapperTestContexts() {}

    static BrokeredIdentityContext context(PresentationType presentationType, String credentialType, String claimsJson)
            throws Exception {
        return context(presentationType, credentialIdOf(presentationType, credentialType), credentialType, claimsJson);
    }

    /** A context whose single credential was answered under the given credential id. */
    static BrokeredIdentityContext context(
            PresentationType presentationType, String credentialId, String credentialType, String claimsJson)
            throws Exception {
        Map<String, Object> claims = JsonSerialization.readValue(claimsJson, new TypeReference<>() {});
        VerifiedCredential credential = new VerifiedCredential(
                credentialId, "https://issuer.example", credentialType, claims, presentationType);

        Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("test-user", config);
        context.getContextData()
                .put(
                        Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY,
                        PresentedCredentials.of(Map.of(credential.credentialId(), credential)));
        return context;
    }

    private static String credentialIdOf(PresentationType presentationType, String credentialType) {
        String format = presentationType == PresentationType.MDOC
                ? Oid4vpConstants.FORMAT_MSO_MDOC
                : Oid4vpConstants.FORMAT_SD_JWT_VC;
        return CredentialId.defaultFor(format, credentialType);
    }
}
