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
import org.keycloak.utils.StringUtil;

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
            String principalCredentialId,
            String principalAttribute,
            boolean principalClaimRequested,
            boolean subjectCredentialMayBeMissing) {

        List<String> problems = referenceProblems(credentialSets, credentials);
        if (problems.isEmpty() && principalClaimRequested) {
            problems = subjectProblems(
                    credentialSets,
                    credentials,
                    principalCredentialId,
                    principalAttribute,
                    subjectCredentialMayBeMissing);
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
            String principalCredentialId,
            String principalAttribute,
            boolean subjectCredentialMayBeMissing) {
        List<String> problems = subjectCredentialMayBeMissing
                ? List.of()
                : principalCoverageProblems(credentialSets, principalCredentialId);
        if (!problems.isEmpty() || credentials.isEmpty()) {
            return problems;
        }
        return principalClaimProblems(credentials, principalCredentialId, principalAttribute);
    }

    /**
     * Every option of every required credential set has to contain the subject credential,
     * otherwise a wallet can satisfy the query with a combination that identifies nobody. Optional
     * sets are exempt because a required set always covers the subject.
     */
    private static List<String> principalCoverageProblems(
            List<CredentialSet> credentialSets, String principalCredentialId) {
        if (credentialSets.isEmpty() || StringUtil.isBlank(principalCredentialId)) {
            return List.of();
        }

        boolean referenced = credentialSets.stream()
                .anyMatch(
                        credentialSet -> credentialSet.referencedCredentialIds().contains(principalCredentialId));
        if (!referenced) {
            return List.of(
                    "principalCredentialId '" + principalCredentialId
                            + "' is not referenced by any credentialSets option, so the subject credential would never be requested");
        }

        List<CredentialSet> requiredSets =
                credentialSets.stream().filter(CredentialSet::required).toList();
        if (requiredSets.isEmpty()) {
            return List.of(
                    "credentialSets contains no entry with required=true, so a wallet could satisfy the query without presenting any credential and no subject would be available");
        }

        List<String> problems = new ArrayList<>();
        for (CredentialSet credentialSet : requiredSets) {
            for (List<String> option : credentialSet.options()) {
                if (!option.contains(principalCredentialId)) {
                    problems.add("principalCredentialId '" + principalCredentialId
                            + "' is missing from the required credentialSets option [" + String.join(", ", option)
                            + "], which could therefore be satisfied without presenting the subject credential");
                }
            }
        }
        return problems;
    }

    /**
     * The subject credential has to request the principal claim in every claim set option. Without
     * a configured subject credential each credential can be the only one presented, so all of them
     * have to carry it.
     */
    private static List<String> principalClaimProblems(
            Map<String, CredentialTypeSpec> credentials, String principalCredentialId, String principalAttribute) {
        if (StringUtil.isBlank(principalAttribute)) {
            return List.of();
        }
        if (StringUtil.isBlank(principalCredentialId)) {
            List<String> problems = new ArrayList<>();
            credentials.forEach((credentialId, credential) ->
                    problems.addAll(principalClaimProblems(credentialId, credential, principalAttribute)));
            return problems;
        }

        CredentialTypeSpec principalCredential = credentials.get(principalCredentialId);
        if (principalCredential == null) {
            return List.of("principalCredentialId '" + principalCredentialId
                    + "' does not name a configured credential. Configured credential ids: "
                    + String.join(", ", credentials.keySet()));
        }
        return principalClaimProblems(principalCredentialId, principalCredential, principalAttribute);
    }

    private static List<String> principalClaimProblems(
            String credentialId, CredentialTypeSpec credential, String principalAttribute) {
        List<ClaimSpec> claimSpecs = credential.claimSpecs();
        List<Integer> principalIndexes = new ArrayList<>();
        for (int i = 0; i < claimSpecs.size(); i++) {
            if (principalAttribute.equals(claimSpecs.get(i).path())) {
                principalIndexes.add(i);
            }
        }
        if (principalIndexes.isEmpty()) {
            return List.of(
                    "credential '" + credentialId + "' does not request the principal claim '"
                            + principalAttribute
                            + "', so a presentation of it alone would not identify the user. Set principalCredentialId to the credential that carries the subject.");
        }

        for (List<Integer> claimSetOption : credential.claimSetOptionIndexes()) {
            if (principalIndexes.stream().noneMatch(claimSetOption::contains)) {
                return List.of(
                        "the principal claim '" + principalAttribute + "' of credential '" + credentialId
                                + "' is not part of every claim set option, so a wallet answering another option would present no subject");
            }
        }
        return List.of();
    }
}
