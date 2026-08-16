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
package de.arbeitsagentur.keycloak.oid4vp.mapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.domain.PresentedCredential;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import org.keycloak.util.JsonSerialization;

/**
 * Reading a claim out of a presented credential, addressed by a {@link ClaimPath}.
 *
 * <p>Shared by the OID4VP mappers and by everything else that reads a configured claim, so a path
 * means the same everywhere: it resolves against the claims of an SD-JWT credential, and against the
 * namespace of an mDoc, which is where its data elements live.
 */
public final class ClaimSelection {

    private ClaimSelection() {}

    /**
     * The node a path resolves against. For an mDoc that is the given namespace, falling back to the
     * one named like the doctype and then, when the credential carries a single namespace, to that
     * one.
     */
    public static JsonNode claimsRoot(PresentedCredential credential, String namespace) {
        JsonNode claims = credential.claimsNode();
        if (claims == null || !Oid4vpConstants.FORMAT_MSO_MDOC.equals(credential.format())) {
            return claims;
        }
        String type = credential.type();
        JsonNode named = claims.get(namespace != null ? namespace : type);
        if (named != null) {
            return named;
        }
        return claims.size() == 1 ? claims.elements().next() : null;
    }

    /**
     * The values the path selects, empty when it selects nothing. A single selected array is read as
     * its elements, which is how a mapper writes multiple values of one claim.
     */
    public static List<String> values(ClaimPath path, JsonNode claimsRoot) {
        List<JsonNode> matches = path.select(claimsRoot);
        if (matches.isEmpty()) {
            return List.of();
        }
        Iterable<JsonNode> selected = matches.size() == 1 && matches.get(0).isArray() ? matches.get(0) : matches;
        // The values end up in the brokered context, whose serialization restores lists by their
        // concrete class, so they must stay plain ArrayLists.
        List<String> values = new ArrayList<>();
        for (JsonNode node : selected) {
            if (!node.isNull()) {
                values.add(value(node));
            }
        }
        return values;
    }

    /**
     * The value as a string. An object or array is serialized with its keys ordered, so the same
     * claim always reads the same, whatever order a wallet rendered it in.
     */
    public static String value(JsonNode node) {
        if (node.isValueNode()) {
            return node.asText();
        }
        try {
            return JsonSerialization.writeValueAsString(ordered(node));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize the claim value", e);
        }
    }

    private static Object ordered(JsonNode node) {
        if (node instanceof ObjectNode object) {
            TreeMap<String, Object> fields = new TreeMap<>();
            Iterator<String> names = object.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                fields.put(name, ordered(object.get(name)));
            }
            return fields;
        }
        if (node.isArray()) {
            List<Object> elements = new ArrayList<>();
            node.forEach(element -> elements.add(ordered(element)));
            return elements;
        }
        return node;
    }
}
