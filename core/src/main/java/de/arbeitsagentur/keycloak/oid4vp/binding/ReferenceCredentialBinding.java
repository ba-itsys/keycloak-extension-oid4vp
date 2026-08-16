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

import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/**
 * Values that tie a credential this Keycloak issues to the login it was issued for.
 *
 * <p>The subject is what the account is recognised by. The reference credential binding is what the
 * credential was issued alongside, so a credential presented next to the credentials of somebody
 * else is not accepted as the subject of a login. This is not the holder binding of OID4VC, which
 * ties a credential to a wallet key. It ties a credential to the other credentials of a
 * presentation.
 *
 * <p>Both are keyed HMACs over a realm secret. The values travel in a credential the wallet shows
 * to other verifiers, and a plain hash of a name and a date of birth is recovered from a candidate
 * list in seconds.
 */
public final class ReferenceCredentialBinding {

    /** Claim of the issued credential carrying the reference credential binding. */
    public static final String REFERENCE_BINDING_CLAIM = "oid4vp_reference_binding";

    /** Entitlement attribute the authenticator records the subject under. */
    public static final String SUBJECT_ATTRIBUTE = "oid4vp.subject";

    /** Entitlement attribute the authenticator records the reference credential binding under. */
    public static final String REFERENCE_BINDING_ATTRIBUTE = "oid4vp.reference-binding";

    private static final Logger LOG = Logger.getLogger(ReferenceCredentialBinding.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SUBJECT_CONTEXT = "oid4vp:subject:";
    private static final String REFERENCE_CONTEXT = "oid4vp:reference:";

    /**
     * The HMAC secrets of one realm, which is all this needs of a Keycloak session. Replaceable in
     * tests with a typed double, the way the trust material providers are.
     */
    public interface RealmSecrets {

        /** The secret new values are computed with. */
        SecretKey active();

        /**
         * Every secret a value may have been computed with, so a key rotation does not invalidate
         * the credentials that are already in wallets.
         */
        List<SecretKey> allAccepted();
    }

    private final RealmSecrets secrets;
    private final ReferenceCredentialBindingProvider selection;

    ReferenceCredentialBinding(RealmSecrets secrets, ReferenceCredentialBindingProvider selection) {
        this.secrets = secrets;
        this.selection = selection;
    }

    /** The binding of the given realm, reading its secrets and its configured selection. */
    public static ReferenceCredentialBinding of(KeycloakSession session, RealmModel realm) {
        return new ReferenceCredentialBinding(
                new SessionRealmSecrets(session, realm), session.getProvider(ReferenceCredentialBindingProvider.class));
    }

    /** The check of this realm, which the identity provider hands to the verifier. */
    public static ReferenceBindingCheck checkOf(KeycloakSession session) {
        return (credentials, credentialId, claimedBinding) ->
                of(session, session.getContext().getRealm()).matches(credentials, credentialId, claimedBinding);
    }

    /**
     * The subject of the credential issued for the given user. It identifies the account without
     * carrying the Keycloak user id into the wallet, where every verifier the credential is shown to
     * would read it.
     */
    public String subjectOf(String userId) {
        return digest(secrets.active(), SUBJECT_CONTEXT + userId);
    }

    /**
     * The reference credential binding of a presentation, over what the {@link
     * ReferenceCredentialBindingProvider} selects. Null when it selects nothing, which leaves the
     * issued credential unbound.
     */
    public String referenceBindingOf(PresentedCredentials credentials, String subjectCredentialId) {
        String material = material(credentials, subjectCredentialId);
        return material == null ? null : digest(secrets.active(), REFERENCE_CONTEXT + material);
    }

    /**
     * Whether the presentation is the one the credential was issued for. Passive realm keys are
     * accepted as well, so a key rotation does not invalidate every issued credential at once.
     *
     * <p>A credential carrying no binding is accepted in any presentation, which is what a
     * credential of another issuer and every credential issued without a binding is.
     */
    public boolean matches(PresentedCredentials credentials, String subjectCredentialId, String claimedBinding) {
        if (claimedBinding == null || claimedBinding.isBlank()) {
            return true;
        }
        String material = material(credentials, subjectCredentialId);
        if (material == null) {
            LOG.debug("The presentation binds to nothing, so the reference credential binding cannot match");
            return false;
        }
        String message = REFERENCE_CONTEXT + material;
        return secrets.allAccepted().stream().anyMatch(secret -> claimedBinding.equals(digest(secret, message)));
    }

    /**
     * The selected credentials as one deterministic string. Credential ids and claim names are
     * ordered, so the same claims of the same wallet always yield the same value. Null when nothing
     * was selected, which is what a presentation of the subject credential alone yields.
     */
    private String material(PresentedCredentials credentials, String subjectCredentialId) {
        Map<String, BoundCredential> selected = selection.bindingMaterial(credentials, subjectCredentialId);
        if (selected == null || selected.isEmpty()) {
            return null;
        }
        try {
            return JsonSerialization.writeValueAsString(new TreeMap<>(selected));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to canonicalize the claims of the reference credential binding", e);
        }
    }

    private static String digest(SecretKey secret, String message) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secret);
            return Base64Url.encode(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute an OID4VP reference credential binding digest", e);
        }
    }

    /** Reads the realm secrets from the session. */
    private record SessionRealmSecrets(KeycloakSession session, RealmModel realm) implements RealmSecrets {

        @Override
        public SecretKey active() {
            SecretKey secret = session.keys().getActiveHmacKey(realm).getSecretKey();
            if (secret == null) {
                throw new IllegalStateException("Realm '" + realm.getName() + "' has no active HMAC key");
            }
            return secret;
        }

        @Override
        public List<SecretKey> allAccepted() {
            // Every realm key that can key an HMAC, so a rotation does not invalidate what is issued
            return session.keys()
                    .getKeysStream(realm)
                    .filter(key -> KeyUse.SIG.equals(key.getUse()))
                    .map(KeyWrapper::getSecretKey)
                    .filter(secret -> secret != null)
                    .toList();
        }
    }
}
