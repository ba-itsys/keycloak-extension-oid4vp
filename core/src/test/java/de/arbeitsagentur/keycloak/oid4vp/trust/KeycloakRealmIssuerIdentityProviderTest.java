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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.arbeitsagentur.keycloak.oid4vp.trust.KeycloakRealmIssuerIdentityProvider.RealmKeyMaterial;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;

class KeycloakRealmIssuerIdentityProviderTest {

    private static final String ISSUER = "https://kc.example/realms/company";
    private static final String BADGE = "https://kc.example/badge";

    @Test
    void bindsRealmKeysToTheRealmIssuer() {
        JWK signatureKey = jwk("realm-key-1", null);
        KeycloakRealmIssuerIdentityProvider provider =
                provider(new FixedRealmKeyMaterial(ISSUER, List.of(signatureKey), List.of()));

        assertThat(provider.trustedIssuerKeys()).containsExactly(new TrustedIssuerKey(ISSUER, signatureKey));
        assertThat(provider.trustedIssuerKeys().get(0).trustedFor(ISSUER)).isTrue();
        assertThat(provider.trustedIssuerKeys().get(0).trustedFor("https://other.example/realms/company"))
                .as("a realm key must not verify a credential of another issuer")
                .isFalse();
    }

    @Test
    void keepsPassiveEncryptionKeysOut() {
        JWK signatureKey = jwk("sig", "sig");
        JWK encryptionKey = jwk("enc", "enc");
        KeycloakRealmIssuerIdentityProvider provider =
                provider(new FixedRealmKeyMaterial(ISSUER, List.of(signatureKey, encryptionKey), List.of()));

        assertThat(provider.trustedIssuerKeys()).containsExactly(new TrustedIssuerKey(ISSUER, signatureKey));
    }

    @Test
    void withoutIssuerNoKeysAreTrusted() {
        KeycloakRealmIssuerIdentityProvider provider =
                provider(new FixedRealmKeyMaterial(null, List.of(jwk("realm-key-1", null)), List.of()));

        assertThat(provider.trustedIssuerKeys())
                .as("keys that cannot be bound to an issuer are not trust material")
                .isEmpty();
    }

    @Test
    void realmKeyCertificatesAreTrustedDirectlyForChainlessCredentials() throws Exception {
        X509Certificate certificate = TestCertificates.selfSigned("CN=Realm Key");
        KeycloakRealmIssuerIdentityProvider provider =
                provider(new FixedRealmKeyMaterial(ISSUER, List.of(), List.of(certificate)));

        assertThat(provider.directIssuerCertificates()).containsExactly(certificate);
        assertThat(provider.resolveX509Trust(null))
                .as("a realm certificate is not a certificate authority")
                .isEmpty();
    }

    @Test
    void servedCredentialTypesAreRequired() {
        KeycloakRealmIssuerIdentityProviderConfig config = new KeycloakRealmIssuerIdentityProviderConfig();
        assertThatThrownBy(() -> config.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("credential types");

        config.setServedCredentialTypes(BADGE);
        assertThat(config.getServedCredentialTypes()).containsExactly(BADGE);
    }

    private static KeycloakRealmIssuerIdentityProvider provider(RealmKeyMaterial realmKeyMaterial) {
        KeycloakRealmIssuerIdentityProviderConfig config = new KeycloakRealmIssuerIdentityProviderConfig();
        config.setAlias("kc-badge-keys");
        config.setServedCredentialTypes(BADGE);
        return new KeycloakRealmIssuerIdentityProvider(config, realmKeyMaterial);
    }

    private static JWK jwk(String keyId, String use) {
        JWK jwk = new ECPublicJWK();
        jwk.setKeyId(keyId);
        jwk.setPublicKeyUse(use);
        return jwk;
    }

    /** Realm key material double, standing in for what the session exposes for the issuing realm. */
    private record FixedRealmKeyMaterial(String issuer, List<JWK> signatureKeys, List<X509Certificate> certificates)
            implements RealmKeyMaterial {}
}
