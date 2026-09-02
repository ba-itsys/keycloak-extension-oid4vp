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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants.*;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceBindingCheck;
import de.arbeitsagentur.keycloak.oid4vp.binding.ReferenceCredentialBinding;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialSet;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpPresentationFlow;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredentials;
import de.arbeitsagentur.keycloak.oid4vp.domain.PrincipalAttribute;
import de.arbeitsagentur.keycloak.oid4vp.domain.RequestedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VerifiedCredential;
import de.arbeitsagentur.keycloak.oid4vp.domain.VpTokenResult;
import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimPath;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpRequestObjectStore;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenProcessor;
import de.arbeitsagentur.keycloak.oid4vp.verification.VpTokenVerifier;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.common.VerificationException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.utils.StringUtil;

/**
 * Processes verified VP token responses into Keycloak {@link BrokeredIdentityContext} objects.
 *
 * <p>Orchestrates the post-response phase of the OID4VP flow: validates the state parameter,
 * delegates VP token verification to {@link VpTokenProcessor}, enforces issuer/credential type
 * allow-lists, resolves the user identity from the configured mapping claim, and populates the
 * brokered identity context with credential claims for downstream mappers.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6">OID4VP 1.0 §8.6 — VP Token Validation</a>
 */
public class Oid4vpCallbackProcessor {

    private static final Logger LOG = Logger.getLogger(Oid4vpCallbackProcessor.class);
    private static final String GENERATED_SUBJECT_PREFIX = "oid4vp-";

    private final IdentityProviderModel idpModel;
    private final Oid4vpConfigProvider configProvider;
    private final UserAuthenticationIdentityProvider<?> provider;
    private final VpTokenVerifier vpTokenVerifier;
    private final ReferenceBindingCheck referenceBindingCheck;

    public Oid4vpCallbackProcessor(
            IdentityProviderModel idpModel,
            Oid4vpConfigProvider configProvider,
            UserAuthenticationIdentityProvider<?> provider,
            VpTokenVerifier vpTokenVerifier,
            ReferenceBindingCheck referenceBindingCheck) {
        this.idpModel = idpModel;
        this.referenceBindingCheck = referenceBindingCheck;
        this.configProvider = configProvider;
        this.provider = provider;
        this.vpTokenVerifier = vpTokenVerifier;
    }

    public BrokeredIdentityContext process(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, String vpToken, String mdocGeneratedNonce) {

        if (requestContext == null || StringUtil.isBlank(requestContext.state())) {
            throw new IdentityBrokerException("Missing request context");
        }

        if (StringUtil.isBlank(vpToken)) {
            throw new IdentityBrokerException("Missing vp_token");
        }

        // Without the expected audience and nonce the verifier would silently skip key binding
        // verification, so an incomplete request context must fail instead of downgrading.
        if (StringUtil.isBlank(requestContext.effectiveClientId()) || StringUtil.isBlank(requestContext.nonce())) {
            throw new IdentityBrokerException("Request context is missing the client_id or nonce");
        }

        LOG.debugf("VP token received (length=%d)", vpToken.length());

        VpTokenResult verified = vpTokenVerifier.process(new VpTokenProcessor.Request(
                vpToken,
                requestContext.effectiveClientId(),
                requestContext.nonce(),
                requestContext.responseUri(),
                mdocGeneratedNonce,
                requestContext.encryptionJwkThumbprint(),
                requestContext.requestedCredentials()));

        VpTokenResult vpResult = credentialsOfThisPresentation(verified);

        VerifiedCredential primary = vpResult.getPrimaryCredential();
        if (primary == null) {
            throw new IdentityBrokerException("No valid credential found in VP token");
        }

        LOG.debugf(
                "Verified credential: format=%s, type=%s, claims=%s",
                primary.presentationType(),
                primary.credentialType(),
                primary.claims().keySet());

        // Every presented credential must come from an allowed issuer, not only the first one: in a
        // multi-credential presentation each credential's claims reach the mappers, so a disallowed
        // issuer must be rejected wherever it appears.
        for (VerifiedCredential presented : vpResult.credentials().values()) {
            String presentedIssuer = presented.issuer();
            if (presentedIssuer != null && !configProvider.isIssuerAllowed(presentedIssuer)) {
                throw new IdentityBrokerException("Issuer not allowed: " + presentedIssuer);
            }
        }

        String issuer = primary.issuer();
        enforceCredentialSets(requestContext, enforceRequestedClaims(requestContext, vpResult));

        String subject;
        String identityKey;
        boolean generatedSubject = false;
        if (configProvider.isTransientUsersEnabled()) {
            subject = buildTransientSubject(requestContext);
            identityKey = primary.generateIdentityKey(subject);
        } else {
            SubjectSource subjectSource = subjectSource(vpResult);
            if (subjectSource == null) {
                subject = generateSubject();
                identityKey = primary.generateCaseInsensitiveIdentityKey(subject);
                generatedSubject = true;
            } else {
                subject = extractSubjectFromCredential(subjectSource);
                identityKey = subjectSource.credential().generateCaseInsensitiveIdentityKey(subject);
            }
        }

        BrokeredIdentityContext context = new BrokeredIdentityContext(identityKey, idpModel);
        context.setIdp(provider);
        context.setUsername(subject);
        context.getContextData()
                .put(Oid4vpMapperUtils.CONTEXT_CREDENTIALS_KEY, PresentedCredentials.of(vpResult.credentials()));
        if (issuer != null) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_ISSUER_KEY, issuer);
        }
        context.getContextData().put(Oid4vpMapperUtils.CONTEXT_SUBJECT_KEY, subject);
        if (generatedSubject) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY, subject);
        }
        Oid4vpPresentationFlow flow = Oid4vpPresentationFlow.of(requestContext.flow());
        if (flow != null) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY, flow.value());
        }
        return context;
    }

    /**
     * The credential the subject is read from, the claim of it that carries the subject, and the
     * node that claim path resolves against.
     */
    private record SubjectSource(VerifiedCredential credential, String claimPath, JsonNode claimsRoot) {}

    /**
     * Where the subject comes from: the first configured principal attribute the wallet presented,
     * so which credential answers is the verifier's decision rather than the wallet's.
     */
    private SubjectSource subjectSource(VpTokenResult vpResult) {
        List<PrincipalAttribute> principalAttributes = configProvider.getPrincipalAttributes();
        if (principalAttributes.isEmpty()) {
            throw new IdentityBrokerException(
                    "No principalAttributes are configured, so nothing says which claim of which credential identifies the user");
        }
        for (PrincipalAttribute principalAttribute : principalAttributes) {
            VerifiedCredential credential = vpResult.credentials().get(principalAttribute.credentialId());
            if (credential == null) {
                continue;
            }
            if (!hasUsableSubjectBinding(vpResult, credential)) {
                // A subject credential this realm issues is always bound to the credentials present at
                // issuance. One presented next to such credentials but carrying no reference credential
                // binding has had that binding withheld, so it does not identify a returning user: the
                // login falls through to a fresh subject, authenticates by other means, and a bound
                // credential is issued again, exactly as on a first login.
                LOG.warnf(
                        "OID4VP IdP '%s': the credential '%s' carries no reference credential binding but was "
                                + "presented alongside credentials a binding would cover, so it is not used as the "
                                + "subject",
                        idpModel.getAlias(), principalAttribute.credentialId());
                continue;
            }
            // The path starts at the root of the presentation, so an mDoc path names its own
            // namespace and none has to be guessed at.
            return new SubjectSource(credential, principalAttribute.claimPath(), credential.claimsNode());
        }
        if (!configProvider.isAllowMissingSubjectCredential()) {
            throw new IdentityBrokerException("None of the credentials carrying the subject ["
                    + String.join(", ", PrincipalAttribute.credentialIdsOf(principalAttributes))
                    + "] was presented");
        }
        return null;
    }

    /**
     * The claim named for this credential becomes the brokered subject. Rejects presentations
     * without a usable value.
     */
    private static String extractSubjectFromCredential(SubjectSource subjectSource) {
        String principalPath = subjectSource.claimPath();
        ClaimPath path = StringUtil.isNotBlank(principalPath) ? ClaimPath.parse(principalPath.trim()) : null;
        if (path == null) {
            throw new IdentityBrokerException("Invalid principal attribute '" + principalPath + "'");
        }
        String subject = firstValue(path, subjectSource.claimsRoot());
        if (StringUtil.isBlank(subject)) {
            throw new IdentityBrokerException("Missing principal claim '" + principalPath + "' in credential");
        }
        return subject;
    }

    private static String firstValue(ClaimPath path, JsonNode root) {
        return path.select(root).stream()
                .filter(JsonNode::isValueNode)
                .map(JsonNode::asText)
                .findFirst()
                .orElse(null);
    }

    /**
     * The presentation without the credentials that were issued for another one. A credential this
     * Keycloak issued says which credentials it was issued alongside, and a wallet holding the
     * credentials of two people could otherwise combine them into a login that belongs to neither.
     *
     * <p>A refused credential counts as not presented at all: it identifies nobody here, and its
     * claims must not reach the mappers either. The login continues on whatever is left, which for
     * the configuration this is built for means a presentation of the PID alone.
     *
     * <p>Credentials carrying no reference credential binding pass untouched, which is what a
     * credential of another issuer and every credential issued without a binding is.
     */
    private VpTokenResult credentialsOfThisPresentation(VpTokenResult vpResult) {
        Map<String, VerifiedCredential> kept = new LinkedHashMap<>();
        vpResult.credentials().forEach((credentialId, credential) -> {
            if (boundToThisPresentation(vpResult, credentialId, credential)) {
                kept.put(credentialId, credential);
            } else {
                LOG.warnf(
                        "OID4VP IdP '%s': the credential '%s' was issued for another presentation and is ignored",
                        idpModel.getAlias(), credentialId);
            }
        });
        if (kept.size() == vpResult.credentials().size()) {
            return vpResult;
        }
        return new VpTokenResult(kept);
    }

    /**
     * Whether the credential was issued for a presentation like this one, judged over the other
     * credentials of the presentation. The credential itself is never part of that material: it is
     * what binds to the others, and at issuance it did not exist yet.
     */
    private boolean boundToThisPresentation(
            VpTokenResult vpResult, String credentialId, VerifiedCredential credential) {
        Object claimed = credential.claims().get(ReferenceCredentialBinding.REFERENCE_BINDING_CLAIM);
        if (claimed == null) {
            return true;
        }
        return referenceBindingCheck.boundToPresentation(
                PresentedCredentials.of(vpResult.credentials()), credentialId, String.valueOf(claimed));
    }

    /**
     * Whether a credential may identify a returning user. A credential carrying a matching reference
     * credential binding may (a non-matching one was already dropped as issued for another
     * presentation). A credential carrying none may too, unless the presentation also contains
     * credentials a binding would cover: a subject credential this realm issues is always bound to such
     * credentials, so one presented next to them without a binding has had it withheld and must not be
     * trusted to identify a user. A subject credential presented on its own, or a login whose subject
     * comes from a credential this realm did not issue and did not bind, has no such material and is
     * unaffected.
     */
    private boolean hasUsableSubjectBinding(VpTokenResult vpResult, VerifiedCredential subjectCredential) {
        boolean carriesBinding =
                subjectCredential.claims().get(ReferenceCredentialBinding.REFERENCE_BINDING_CLAIM) != null;
        if (carriesBinding) {
            return true;
        }
        return !referenceBindingCheck.bindsToOtherCredentials(
                PresentedCredentials.of(vpResult.credentials()), subjectCredential.credentialId());
    }

    /**
     * A pseudonymous subject for a presentation that carried no subject credential. Nothing in the
     * presentation identifies the user, so the login that follows establishes which user this
     * subject belongs to, and an issuer puts it into the credential that identifies them next time.
     */
    private static String generateSubject() {
        return GENERATED_SUBJECT_PREFIX + UUID.randomUUID();
    }

    private String buildTransientSubject(Oid4vpRequestObjectStore.RequestContextEntry requestContext) {
        String state = StringUtil.isNotBlank(requestContext.state()) ? requestContext.state() : "unknown";
        LOG.debugf("OID4VP IdP '%s': generating transient subject for state '%s'", idpModel.getAlias(), state);
        return "transient-" + state + "-" + UUID.randomUUID();
    }

    /**
     * Validates that every verified credential contains the claims its DCQL credential entry
     * requested: all claims when no claim sets are defined, otherwise at least one complete
     * claim_sets option. Entries are looked up by the credential id the wallet answered under, so
     * two entries of the same credential type stay distinguishable.
     *
     * @return the credential ids whose presentation satisfied their requested claims
     */
    private Set<String> enforceRequestedClaims(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, VpTokenResult vpResult) {
        List<RequestedCredential> requestedCredentials = requestContext.requestedCredentials();
        if (requestedCredentials == null || requestedCredentials.isEmpty()) {
            return Set.copyOf(vpResult.credentials().keySet());
        }

        Set<String> satisfied = new LinkedHashSet<>();
        for (Map.Entry<String, VerifiedCredential> presented :
                vpResult.credentials().entrySet()) {
            String credentialId = presented.getKey();
            VerifiedCredential credential = presented.getValue();
            RequestedCredential requested = requestedCredentials.stream()
                    .filter(candidate -> credentialId.equals(candidate.id()))
                    .findFirst()
                    .orElse(null);
            if (requested == null) {
                throw new IdentityBrokerException(
                        "VP token contains the credential id '" + credentialId + "', which was not requested");
            }
            if (!requested.matches(credential)) {
                throw new IdentityBrokerException("Credential type not trusted by this OID4VP IdP: the query requested"
                        + " format '" + requested.format() + "' and type '" + requested.describeTypes()
                        + "' under credential id '" + credentialId + "', but the wallet presented type '"
                        + credential.credentialType() + "'");
            }
            try {
                requested.checkIfSatisfiedBy(credential.claimsNode());
            } catch (VerificationException e) {
                throw new IdentityBrokerException(e.getMessage(), e);
            }
            satisfied.add(credentialId);
        }
        return satisfied;
    }

    /**
     * Validates that the presented credentials satisfy one complete option of every required
     * credential set. Only credentials that passed their own claim validation count, so a
     * credential that withheld requested claims cannot satisfy an option. Without credential
     * sets every requested credential is required (OID4VP 1.0, section 6.1), so a wallet cannot
     * silently omit credentials whose claims the mappers depend on.
     */
    private void enforceCredentialSets(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, Set<String> satisfiedCredentialIds) {
        List<CredentialSet> credentialSets = requestContext.credentialSets();
        if (credentialSets == null || credentialSets.isEmpty()) {
            enforceAllRequestedCredentialsPresented(requestContext, satisfiedCredentialIds);
            return;
        }
        for (CredentialSet credentialSet : credentialSets) {
            if (!credentialSet.required()) {
                continue;
            }
            boolean anyOptionSatisfied = credentialSet.options().stream().anyMatch(satisfiedCredentialIds::containsAll);
            if (!anyOptionSatisfied) {
                List<String> preferredOption = credentialSet.options().get(0);
                List<String> missing = preferredOption.stream()
                        .filter(credentialId -> !satisfiedCredentialIds.contains(credentialId))
                        .toList();
                throw new IdentityBrokerException("The presentation does not satisfy any option of a required "
                        + "credential set. The preferred option [" + String.join(", ", preferredOption)
                        + "] is missing: " + String.join(", ", missing));
            }
        }
    }

    private void enforceAllRequestedCredentialsPresented(
            Oid4vpRequestObjectStore.RequestContextEntry requestContext, Set<String> satisfiedCredentialIds) {
        List<RequestedCredential> requestedCredentials = requestContext.requestedCredentials();
        if (requestedCredentials == null) {
            return;
        }
        // The subject credential this realm issues may be absent when the configuration expects
        // that: the login then continues towards issuing it.
        Set<String> allowedMissing = configProvider.isAllowMissingSubjectCredential()
                ? Set.copyOf(PrincipalAttribute.credentialIdsOf(configProvider.getPrincipalAttributes()))
                : Set.of();
        List<String> missing = requestedCredentials.stream()
                .map(RequestedCredential::id)
                .filter(credentialId -> !satisfiedCredentialIds.contains(credentialId))
                .filter(credentialId -> !allowedMissing.contains(credentialId))
                .toList();
        if (!missing.isEmpty()) {
            throw new IdentityBrokerException(
                    "The presentation is missing requested credentials: " + String.join(", ", missing));
        }
    }
}
