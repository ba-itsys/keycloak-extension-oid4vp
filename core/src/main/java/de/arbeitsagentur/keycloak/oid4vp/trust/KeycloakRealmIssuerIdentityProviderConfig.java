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

import java.util.List;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

/**
 * Configuration of the trust material identity provider for credentials this Keycloak issues
 * itself.
 *
 * <p>The trust material is the signature key material of the issuing realm, so nothing has to be
 * pasted and a key rotation takes effect without reconfiguration.
 */
public class KeycloakRealmIssuerIdentityProviderConfig extends IdentityProviderModel {

    public static final String ISSUER_REALM = "issuerRealm";
    public static final String ISSUER = "issuer";
    public static final String SERVED_CREDENTIAL_TYPES = ServedCredentialTypes.CONFIG_KEY;

    public KeycloakRealmIssuerIdentityProviderConfig() {}

    public KeycloakRealmIssuerIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        if (getServedCredentialTypes().isEmpty()) {
            throw new IllegalArgumentException(
                    "Configure the credential types this Keycloak issues, otherwise its realm keys would be trusted "
                            + "for every credential the verifier requests");
        }
    }

    /** The realm whose keys sign the credentials; empty means the realm the verifier runs in. */
    public String getIssuerRealm() {
        return getConfig().get(ISSUER_REALM);
    }

    public void setIssuerRealm(String realmName) {
        getConfig().put(ISSUER_REALM, realmName);
    }

    /**
     * The credential {@code iss} to bind the keys to. Empty derives it from the issuing realm, which
     * is the value Keycloak's JWT VC issuer metadata publishes. Configure it when the credentials
     * were issued under a different frontend URL.
     */
    public String getIssuer() {
        return getConfig().get(ISSUER);
    }

    public void setIssuer(String issuer) {
        getConfig().put(ISSUER, issuer);
    }

    public List<String> getServedCredentialTypes() {
        return ServedCredentialTypes.of(this);
    }

    public void setServedCredentialTypes(String commaSeparatedCredentialTypes) {
        getConfig().put(SERVED_CREDENTIAL_TYPES, commaSeparatedCredentialTypes);
    }
}
