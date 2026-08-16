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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Validates the credential set configuration of an OID4VP identity provider.
 *
 * <p>Runs when the identity provider is saved and again when the DCQL query is built. The rules
 * that need the credentials aggregated from the mappers are skipped for an empty credential map,
 * which is the state of an identity provider that has no mappers yet. The build time run is what
 * catches mapper edits, since the identity provider mapper endpoints have no validation hook.
 *
 * <p>Every problem is an error. The returned messages are meant for the admin console.
 */
public final class Oid4vpCredentialSetsValidator {

    private Oid4vpCredentialSetsValidator() {}

    /**
     * @param credentials the credentials aggregated from the mappers, keyed by credential id, or
     *     empty to check only what the identity provider configuration says on its own
     * @param principalAttributes the credentials the subject may be read from, each with the claim
     *     of it that carries the subject
     * @param principalClaimRequested false when the subject comes from a transient user, so no
     *     credential has to carry the principal claim
     * @param subjectCredentialMayBeMissing whether a presentation without the subject credential is
     *     expected, which lifts the requirement that every required credential set option carries
     *     it. The subject is then established by the login that follows instead of by the
     *     presentation.
     * @return the problems of this configuration, empty when it is valid
     */
    public static List<String> problems(
            List<CredentialSet> credentialSets,
            Map<String, CredentialTypeSpec> credentials,
            List<PrincipalAttribute> principalAttributes,
            boolean principalClaimRequested,
            boolean subjectCredentialMayBeMissing) {

        List<String> problems = referenceProblems(credentialSets, credentials);
        if (problems.isEmpty() && principalClaimRequested) {
            problems = subjectProblems(credentialSets, credentials, principalAttributes, subjectCredentialMayBeMissing);
        }
        return List.copyOf(problems);
    }

    /** Every referenced credential id has to be a legal DCQL id naming a configured credential. */
    private static List<String> referenceProblems(
            List<CredentialSet> credentialSets, Map<String, CredentialTypeSpec> credentials) {
        List<String> problems = new ArrayList<>();
        for (CredentialSet credentialSet : credentialSets) {
            for (String credentialId : credentialSet.referencedCredentialIds()) {
                if (!CredentialId.isValid(credentialId)) {
                    problems.add("credentialSets references the credential id '" + credentialId
                            + "', which is not a valid DCQL id: only letters, digits, '_' and '-' are allowed");
                } else if (!credentials.isEmpty() && !credentials.containsKey(credentialId)) {
                    problems.add("credentialSets references the credential id '" + credentialId
                            + "', but no mapper produces it. Configured credential ids: "
                            + String.join(", ", credentials.keySet()));
                }
            }
        }
        return problems;
    }

    /** Every combination a wallet may present has to yield a subject. */
    private static List<String> subjectProblems(
            List<CredentialSet> credentialSets,
            Map<String, CredentialTypeSpec> credentials,
            List<PrincipalAttribute> principalAttributes,
            boolean subjectCredentialMayBeMissing) {
        if (principalAttributes.isEmpty()) {
            return List.of(
                    "principalAttributes is required: it names the credentials the subject is read from, and the claim of each that carries it");
        }
        List<String> problems =
                principalCoverageProblems(credentialSets, principalAttributes, subjectCredentialMayBeMissing);
        if (!problems.isEmpty() || credentials.isEmpty()) {
            return problems;
        }
        return principalClaimProblems(credentials, principalAttributes);
    }

    /**
     * Every option of every required credential set has to contain one of the subject credentials,
     * otherwise a wallet can satisfy the query with a combination that identifies nobody. Optional
     * sets are exempt because a required set always covers the subject, and a configuration that
     * expects the subject credential to be missing is exempt from that last rule alone.
     */
    private static List<String> principalCoverageProblems(
            List<CredentialSet> credentialSets,
            List<PrincipalAttribute> principalAttributes,
            boolean subjectCredentialMayBeMissing) {
        if (credentialSets.isEmpty()) {
            return List.of();
        }
        List<String> subjectCredentialIds = PrincipalAttribute.credentialIdsOf(principalAttributes);

        List<String> problems = new ArrayList<>();
        for (String subjectCredentialId : subjectCredentialIds) {
            boolean referenced = credentialSets.stream()
                    .anyMatch(credentialSet ->
                            credentialSet.referencedCredentialIds().contains(subjectCredentialId));
            if (!referenced) {
                problems.add(
                        "principalAttributes names '" + subjectCredentialId
                                + "', which no credentialSets option references, so that subject credential would never be requested");
            }
        }
        if (!problems.isEmpty()) {
            return problems;
        }

        List<CredentialSet> requiredSets =
                credentialSets.stream().filter(CredentialSet::required).toList();
        if (requiredSets.isEmpty()) {
            return List.of(
                    "credentialSets contains no entry with required=true, so a wallet could satisfy the query without presenting any credential and no subject would be available");
        }
        if (subjectCredentialMayBeMissing) {
            return List.of();
        }

        for (CredentialSet credentialSet : requiredSets) {
            for (List<String> option : credentialSet.options()) {
                if (option.stream().noneMatch(subjectCredentialIds::contains)) {
                    problems.add("the required credentialSets option [" + String.join(", ", option)
                            + "] contains none of the subject credentials [" + String.join(", ", subjectCredentialIds)
                            + "], so it could be satisfied without presenting one");
                }
            }
        }
        return problems;
    }

    /** Every subject credential has to request its claim in every claim set option. */
    private static List<String> principalClaimProblems(
            Map<String, CredentialTypeSpec> credentials, List<PrincipalAttribute> principalAttributes) {
        List<String> problems = new ArrayList<>();
        for (PrincipalAttribute principal : principalAttributes) {
            CredentialTypeSpec credential = credentials.get(principal.credentialId());
            if (credential == null) {
                problems.add("principalAttributes names '" + principal.credentialId()
                        + "', which is not a configured credential. Configured credential ids: "
                        + String.join(", ", credentials.keySet()));
                continue;
            }
            problems.addAll(principalClaimProblems(principal, credential));
        }
        return problems;
    }

    /**
     * A subject credential has to request its claim. For an mDoc the path names the namespace
     * before the element, and DCQL asks for the two separately, so both halves have to match a
     * requested claim.
     */
    private static List<String> principalClaimProblems(PrincipalAttribute principal, CredentialTypeSpec credential) {
        String credentialId = principal.credentialId();
        if (!Oid4vpConstants.FORMAT_MSO_MDOC.equals(credential.format())) {
            return claimProblems(credentialId, credential, principal.claimPath(), null);
        }
        String namespace = principal.mdocNamespace();
        if (namespace == null) {
            return List.of("principalAttributes names '" + credentialId + ":" + principal.claimPath()
                    + "', but an mDoc keeps its data elements inside a namespace, so the path has to name the"
                    + " namespace before the element");
        }
        return claimProblems(credentialId, credential, principal.mdocElementPath(), namespace);
    }

    private static List<String> claimProblems(
            String credentialId, CredentialTypeSpec credential, String claimPath, String namespace) {
        List<ClaimSpec> claimSpecs = credential.claimSpecs();
        List<Integer> principalIndexes = new ArrayList<>();
        for (int i = 0; i < claimSpecs.size(); i++) {
            ClaimSpec claimSpec = claimSpecs.get(i);
            boolean sameNamespace = namespace == null || namespace.equals(claimSpec.namespace());
            if (sameNamespace && claimPath.equals(claimSpec.path())) {
                principalIndexes.add(i);
            }
        }
        if (principalIndexes.isEmpty()) {
            return List.of("credential '" + credentialId + "' does not request the claim '" + claimPath
                    + "' that principalAttributes reads its subject from");
        }

        for (List<Integer> claimSetOption : credential.claimSetOptionIndexes()) {
            if (principalIndexes.stream().noneMatch(claimSetOption::contains)) {
                return List.of(
                        "the claim '" + claimPath + "' of credential '" + credentialId
                                + "' is not part of every claim set option, so a wallet answering another option would present no subject");
            }
        }
        return List.of();
    }
}
