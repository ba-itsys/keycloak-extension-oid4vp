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
package de.arbeitsagentur.keycloak.oid4vp.it;

import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.testframework.realm.ClientConfigBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.RealmConfigBuilder;

// The realm the end-to-end tests log in to with the public PKCE test client
public class Oid4vpRealmConfig implements RealmConfig {

    public static final String REALM = "wallet-demo";
    public static final String CLIENT_ID = "wallet-mock";

    @Override
    public RealmConfigBuilder configure(RealmConfigBuilder realm) {
        return realm.name(REALM)
                .client(ClientConfigBuilder.create()
                        .clientId(CLIENT_ID)
                        .publicClient(true)
                        .protocol("openid-connect")
                        .directAccessGrantsEnabled(true)
                        .redirectUris("*")
                        .webOrigins("*")
                        .attribute("pkce.code.challenge.method", "S256")
                        .protocolMappers(List.of(credentialFamilyNameIdTokenMapper()))
                        .build());
    }

    // Maps the credentialFamilyName session note set by the IdP session mapper into the id token
    private static ProtocolMapperRepresentation credentialFamilyNameIdTokenMapper() {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("credential-family-name-id-token");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usersessionmodel-note-mapper");
        mapper.setConfig(Map.of(
                "user.session.note", "credentialFamilyName",
                "claim.name", "credential_family_name",
                "jsonType.label", "String",
                "id.token.claim", "true"));
        return mapper;
    }
}
