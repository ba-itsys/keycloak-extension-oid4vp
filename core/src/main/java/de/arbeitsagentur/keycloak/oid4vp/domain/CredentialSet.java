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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * One DCQL {@code credential_sets} entry, listing the alternative combinations of credential ids
 * that satisfy the verifier. The wallet has to satisfy one option of every required set.
 *
 * <p>The identity provider configures it verbatim in DCQL syntax, so that an admin writes what the
 * specification defines rather than a translated dialect:
 *
 * <pre>{@code
 * [{"purpose": "Login", "options": [["pid", "mdl"], ["pid"]]},
 *  {"options": [["diploma"]], "required": false}]
 * }</pre>
 *
 * @param options alternative credential id combinations, most preferred first
 * @param required whether the wallet has to satisfy one of the options. DCQL defaults this to true.
 * @param purpose description the wallet shows to the user
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2">OID4VP 1.0 §6.2 — Credential Set Query</a>
 */
public record CredentialSet(List<List<String>> options, boolean required, String purpose) {

    public CredentialSet {
        options = options != null ? options.stream().map(List::copyOf).toList() : List.of();
        if (options.isEmpty() || options.stream().anyMatch(List::isEmpty)) {
            throw new IllegalArgumentException("A credential set needs at least one non-empty option");
        }
    }

    /**
     * Parses the configured DCQL {@code credential_sets} value, rejecting everything the DCQL
     * schema does not allow so that a misconfiguration surfaces as a config error instead of an
     * opaque rejection by the wallet.
     *
     * @throws IllegalArgumentException with an admin readable message naming the first problem
     */
    public static List<CredentialSet> parse(ObjectMapper objectMapper, String credentialSetsJson) {
        JsonNode root;
        try {
            root = objectMapper.readTree(credentialSetsJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("credentialSets is not valid JSON: " + e.getMessage(), e);
        }
        if (root == null || !root.isArray()) {
            throw new IllegalArgumentException("credentialSets must be a JSON array of credential set objects");
        }

        List<CredentialSet> credentialSets = new ArrayList<>();
        for (JsonNode entry : root) {
            credentialSets.add(parseEntry(entry));
        }
        return List.copyOf(credentialSets);
    }

    private static CredentialSet parseEntry(JsonNode entry) {
        if (!entry.isObject()) {
            throw new IllegalArgumentException("credentialSets entries must be JSON objects");
        }
        JsonNode optionsNode = entry.get(Oid4vpConstants.DCQL_OPTIONS);
        if (optionsNode == null || !optionsNode.isArray() || optionsNode.isEmpty()) {
            throw new IllegalArgumentException("every credentialSets entry needs a non-empty 'options' array");
        }

        List<List<String>> options = new ArrayList<>();
        for (JsonNode optionNode : optionsNode) {
            if (!optionNode.isArray() || optionNode.isEmpty()) {
                throw new IllegalArgumentException(
                        "every entry of 'options' must be a non-empty array of credential ids");
            }
            List<String> option = new ArrayList<>();
            for (JsonNode idNode : optionNode) {
                if (!idNode.isTextual()) {
                    throw new IllegalArgumentException("credential ids in 'options' must be strings");
                }
                option.add(idNode.asText());
            }
            options.add(option);
        }

        // An explicit null is treated as absent, because a serialized credential set carries null
        // for a purpose that was never configured.
        JsonNode requiredNode = presentNode(entry, Oid4vpConstants.DCQL_REQUIRED);
        if (requiredNode != null && !requiredNode.isBoolean()) {
            throw new IllegalArgumentException("'required' of a credentialSets entry must be a boolean");
        }
        JsonNode purposeNode = presentNode(entry, Oid4vpConstants.DCQL_PURPOSE);
        if (purposeNode != null && !purposeNode.isTextual()) {
            throw new IllegalArgumentException("'purpose' of a credentialSets entry must be a string");
        }

        return new CredentialSet(
                options,
                requiredNode == null || requiredNode.asBoolean(),
                purposeNode != null ? purposeNode.asText() : null);
    }

    private static JsonNode presentNode(JsonNode entry, String field) {
        JsonNode node = entry.get(field);
        return node == null || node.isNull() ? null : node;
    }

    public List<String> referencedCredentialIds() {
        return options.stream().flatMap(List::stream).distinct().toList();
    }
}
