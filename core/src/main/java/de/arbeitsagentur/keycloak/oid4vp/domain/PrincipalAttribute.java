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

import de.arbeitsagentur.keycloak.oid4vp.mapper.ClaimPath;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.keycloak.utils.StringUtil;

/**
 * One credential the subject of a login may be read from, and the claim of it that carries the
 * subject. Credentials do not agree on where the subject sits, so the claim belongs to the
 * credential rather than to the identity provider.
 *
 * <p>Configured as a comma separated list of {@code credentialId:claimPath} entries. The first
 * entry a wallet presented supplies the subject, so which credential answers is the verifier's
 * decision rather than the wallet's.
 *
 * <p>The claim path starts at the root of what the credential presents: {@code employee:sub} for an
 * SD-JWT credential, {@code pid_mdoc:eu\.europa\.ec\.eudi\.pid\.1.family_name} for an mDoc,
 * whose data elements sit inside a namespace and whose dots are therefore escaped.
 *
 * @param credentialId the DCQL credential id, as the mappers produce it
 * @param claimPath the claim of that credential, in the dot notation the mappers use
 */
public record PrincipalAttribute(String credentialId, String claimPath) {

    private static final String ENTRY_SEPARATOR = ",";
    private static final char CLAIM_SEPARATOR = ':';

    /**
     * @throws IllegalArgumentException when an entry is malformed or names a credential twice
     */
    public static List<PrincipalAttribute> parse(String configured) {
        if (StringUtil.isBlank(configured)) {
            return List.of();
        }
        List<PrincipalAttribute> principalAttributes = new ArrayList<>();
        Set<String> credentialIds = new LinkedHashSet<>();
        for (String entry : configured.split(ENTRY_SEPARATOR)) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            principalAttributes.add(parseEntry(trimmed, credentialIds));
        }
        return List.copyOf(principalAttributes);
    }

    private static PrincipalAttribute parseEntry(String entry, Set<String> credentialIds) {
        int separator = entry.indexOf(CLAIM_SEPARATOR);
        if (separator < 0) {
            throw new IllegalArgumentException("principalAttributes entry '" + entry
                    + "' names no claim. Write it as 'credentialId:claimPath', because credentials do not agree on"
                    + " where the subject sits.");
        }
        if (entry.indexOf(CLAIM_SEPARATOR, separator + 1) >= 0) {
            // A credential id never contains a colon, so a second one means a credential type was
            // pasted where its DCQL id belongs.
            throw new IllegalArgumentException("principalAttributes entry '" + entry
                    + "' holds more than one ':'. An entry is 'credentialId:claimPath', and the credential id is the"
                    + " DCQL id of a mapper rather than the credential type.");
        }
        String credentialId = entry.substring(0, separator).trim();
        String claimPath = entry.substring(separator + 1).trim();
        if (credentialId.isEmpty() || claimPath.isEmpty()) {
            throw new IllegalArgumentException(
                    "principalAttributes entry '" + entry + "' needs both a credential id and a claim path");
        }
        if (!CredentialId.isValid(credentialId)) {
            throw new IllegalArgumentException("principalAttributes entry '" + entry
                    + "' names the credential id '" + credentialId
                    + "', which is not a valid DCQL id: only letters, digits, '_' and '-' are allowed");
        }
        if (ClaimPath.parse(claimPath) == null) {
            throw new IllegalArgumentException("principalAttributes entry '" + entry + "' names the claim path '"
                    + claimPath + "', which is not a valid claim path");
        }
        if (!credentialIds.add(credentialId)) {
            throw new IllegalArgumentException("principalAttributes names the credential '" + credentialId
                    + "' more than once, so it is unclear which claim carries the subject");
        }
        return new PrincipalAttribute(credentialId, claimPath);
    }

    /**
     * The mDoc namespace this path names, which is its first step, or null when the path has a
     * single step. DCQL asks for the namespace and the element separately, so the two halves of the
     * path are needed apart from each other.
     */
    public String mdocNamespace() {
        int separator = unescapedDot(claimPath);
        return separator < 0 ? null : unescape(claimPath.substring(0, separator));
    }

    /** The path inside {@link #mdocNamespace()}, or the whole path when it names no namespace. */
    public String mdocElementPath() {
        int separator = unescapedDot(claimPath);
        return separator < 0 ? claimPath : claimPath.substring(separator + 1);
    }

    /** The index of the first dot that separates steps, skipping the escaped ones. */
    private static int unescapedDot(String path) {
        for (int i = 0; i < path.length(); i++) {
            char character = path.charAt(i);
            if (character == '\\') {
                i++;
            } else if (character == '.') {
                return i;
            }
        }
        return -1;
    }

    private static String unescape(String step) {
        return step.replace("\\", "");
    }

    /** The credential ids of the given entries, in order. */
    public static List<String> credentialIdsOf(List<PrincipalAttribute> principalAttributes) {
        return principalAttributes.stream()
                .map(PrincipalAttribute::credentialId)
                .toList();
    }
}
