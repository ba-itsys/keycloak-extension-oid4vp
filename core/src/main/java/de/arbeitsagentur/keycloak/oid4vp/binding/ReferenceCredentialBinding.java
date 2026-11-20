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
import java.security.MessageDigest;
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
 * Computes the reference credential binding of a credential this Keycloak issues. It records the
 * credentials that were presented when the credential was issued, so a credential presented next to the
 * credentials of somebody else is not accepted as the subject of a login. This differs from the holder
 * binding of OID4VC, which ties a credential to a wallet key.
 *
 * <p>The binding is an HMAC keyed with the dedicated realm key of {@link ReferenceBindingKeyProvider}.
 * The wallet shows the credential to other verifiers, and they recover a plain hash of a name and a date
 * of birth from a candidate list in seconds.
 */
public final class ReferenceCredentialBinding {

    public static final String DEFAULT_REFERENCE_BINDING_CLAIM = "oid4vp_reference_binding";

    public static final String SUBJECT_ATTRIBUTE = "oid4vp.subject";

    public static final String REFERENCE_BINDING_ATTRIBUTE = "oid4vp.reference-binding";

    private static final Logger LOG = Logger.getLogger(ReferenceCredentialBinding.class);
    private static final String REFERENCE_CONTEXT = "oid4vp:reference:";

    // Narrows the Keycloak session to the binding secrets of one realm, so a test can pass its own secrets.
    public interface RealmSecrets {

        SecretKey active();

        // Returns every secret a value may have been computed with, so a key rotation keeps issued credentials valid.
        List<SecretKey> allAccepted();
    }

    private final RealmSecrets secrets;
    private final ReferenceCredentialBindingProvider selection;

    ReferenceCredentialBinding(RealmSecrets secrets, ReferenceCredentialBindingProvider selection) {
        this.secrets = secrets;
        this.selection = selection;
    }

    public static ReferenceCredentialBinding of(KeycloakSession session, RealmModel realm) {
        return new ReferenceCredentialBinding(
                new SessionRealmSecrets(session, realm), session.getProvider(ReferenceCredentialBindingProvider.class));
    }

    public static ReferenceBindingCheck checkOf(KeycloakSession session) {
        return new ReferenceBindingCheck() {
            @Override
            public boolean boundToPresentation(
                    PresentedCredentials credentials, String subjectCredentialId, String claimedBinding) {
                return of(session, session.getContext().getRealm())
                        .matches(credentials, subjectCredentialId, claimedBinding);
            }

            @Override
            public boolean bindsToOtherCredentials(PresentedCredentials credentials, String subjectCredentialId) {
                return of(session, session.getContext().getRealm())
                        .bindsToOtherCredentials(credentials, subjectCredentialId);
            }
        };
    }

    public boolean bindsToOtherCredentials(PresentedCredentials credentials, String subjectCredentialId) {
        return material(credentials, subjectCredentialId) != null;
    }

    /**
     * Computes the reference credential binding of a presentation over what the {@link
     * ReferenceCredentialBindingProvider} selects. Returns null when it selects nothing, and the issued
     * credential is then unbound.
     */
    public String referenceBindingOf(PresentedCredentials credentials, String subjectCredentialId) {
        String material = material(credentials, subjectCredentialId);
        return material == null ? null : digest(secrets.active(), REFERENCE_CONTEXT + material);
    }

    /**
     * Reports whether the presentation is the one the credential was issued for. Passive binding keys are
     * accepted as well, so a key rotation does not invalidate every issued credential at once. A
     * credential carrying no binding is accepted in any presentation. That covers a credential of another
     * issuer and every credential issued without a binding.
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
        byte[] claimed = claimedBinding.getBytes(StandardCharsets.UTF_8);
        return secrets.allAccepted().stream()
                .anyMatch(secret ->
                        MessageDigest.isEqual(claimed, digest(secret, message).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Renders the selected credentials as one deterministic string with credential ids and claim names
     * ordered, so that the same claims of the same wallet always yield the same value. Returns null when
     * nothing was selected, which is the case for a presentation of the subject credential alone.
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
            Mac mac = Mac.getInstance(ReferenceBindingKeyProvider.HMAC_ALGORITHM);
            mac.init(secret);
            return Base64Url.encode(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute an OID4VP reference credential binding digest", e);
        }
    }

    private record SessionRealmSecrets(KeycloakSession session, RealmModel realm) implements RealmSecrets {

        @Override
        public SecretKey active() {
            return session.keys()
                    .getActiveKey(realm, KeyUse.SIG, ReferenceBindingKeyProvider.ALGORITHM)
                    .getSecretKey();
        }

        @Override
        public List<SecretKey> allAccepted() {
            return session.keys()
                    .getKeysStream(realm, KeyUse.SIG, ReferenceBindingKeyProvider.ALGORITHM)
                    .map(KeyWrapper::getSecretKey)
                    .toList();
        }
    }
}
