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
package de.arbeitsagentur.keycloak.oid4vp;

import static org.assertj.core.api.Assertions.*;

import com.upokecenter.cbor.CBORObject;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MdocVerifierTest {

    private MdocVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new MdocVerifier();
    }

    @Test
    void isMdoc_validMdocWithDocuments_returnsTrue() {
        CBORObject root = CBORObject.NewMap();
        root.Add("documents", CBORObject.NewArray());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThat(verifier.isMdoc(token)).isTrue();
    }

    @Test
    void isMdoc_validMdocWithNameSpaces_returnsTrue() {
        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", CBORObject.NewMap());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThat(verifier.isMdoc(token)).isTrue();
    }

    @Test
    void isMdoc_sdJwtString_returnsFalse() {
        assertThat(verifier.isMdoc("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~"))
                .isFalse();
    }

    @Test
    void isMdoc_null_returnsFalse() {
        assertThat(verifier.isMdoc(null)).isFalse();
    }

    @Test
    void isMdoc_blank_returnsFalse() {
        assertThat(verifier.isMdoc("")).isFalse();
    }

    @Test
    void verify_simpleNameSpaces_extractsNamespacePrefixedClaims() {
        CBORObject item1 = CBORObject.NewMap();
        item1.Add("elementIdentifier", "given_name");
        item1.Add("elementValue", "John");

        CBORObject item2 = CBORObject.NewMap();
        item2.Add("elementIdentifier", "family_name");
        item2.Add("elementValue", "Doe");

        CBORObject elements = CBORObject.NewArray();
        elements.Add(item1);
        elements.Add(item2);

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add("org.iso.18013.5.1", elements);

        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", nameSpaces);
        root.Add("docType", "org.iso.18013.5.1.mDL");

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        MdocVerifier.VerificationResult result =
                verifier.verify(token, "client-id", "nonce", "response-uri", null, true, true);

        assertThat(result.docType()).isEqualTo("org.iso.18013.5.1.mDL");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "John");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/family_name", "Doe");
    }

    @Test
    void verify_emptyDocumentsArray_throws() {
        CBORObject root = CBORObject.NewMap();
        root.Add("documents", CBORObject.NewArray());
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThatThrownBy(() -> verifier.verify(token, "client-id", "nonce", "uri", null, true, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Empty documents array");
    }

    @Test
    void verify_unknownStructure_throws() {
        CBORObject root = CBORObject.NewMap();
        root.Add("something_else", "value");
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        assertThatThrownBy(() -> verifier.verify(token, "client-id", "nonce", "uri", null, true, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown mDoc structure");
    }

    @Test
    void verify_noKeyMaterial_notSkipping_throws() {
        CBORObject item = CBORObject.NewMap();
        item.Add("elementIdentifier", "given_name");
        item.Add("elementValue", "John");

        CBORObject elements = CBORObject.NewArray();
        elements.Add(item);

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add("org.iso.18013.5.1", elements);

        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", nameSpaces);
        root.Add("docType", "org.iso.18013.5.1.mDL");

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        // trustX5c=false, skipSig=false → should throw since no key material
        assertThatThrownBy(() -> verifier.verify(token, "client-id", "nonce", "uri", null, false, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No key material available");
    }

    @Test
    void verify_multipleNamespaces_prefixedCorrectly() {
        CBORObject item1 = CBORObject.NewMap();
        item1.Add("elementIdentifier", "given_name");
        item1.Add("elementValue", "Alice");

        CBORObject item2 = CBORObject.NewMap();
        item2.Add("elementIdentifier", "age_over_18");
        item2.Add("elementValue", true);

        CBORObject ns1 = CBORObject.NewArray();
        ns1.Add(item1);

        CBORObject ns2 = CBORObject.NewArray();
        ns2.Add(item2);

        CBORObject nameSpaces = CBORObject.NewMap();
        nameSpaces.Add("org.iso.18013.5.1", ns1);
        nameSpaces.Add("org.iso.18013.5.1.aamva", ns2);

        CBORObject root = CBORObject.NewMap();
        root.Add("nameSpaces", nameSpaces);
        root.Add("docType", "org.iso.18013.5.1.mDL");

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(root.EncodeToBytes());

        MdocVerifier.VerificationResult result =
                verifier.verify(token, "client-id", "nonce", "response-uri", null, true, true);

        assertThat(result.claims()).containsEntry("org.iso.18013.5.1/given_name", "Alice");
        assertThat(result.claims()).containsEntry("org.iso.18013.5.1.aamva/age_over_18", true);
    }
}
