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
package de.arbeitsagentur.keycloak.oid4vp.conformance.verifier;

import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;

// The credential format profile a verifier conformance scenario runs with. The mappers drive
// both the generated DCQL query and the claim-to-attribute mapping.
public enum CredentialProfile {
    SD_JWT_VC(
            "sdjwt_urn_eudi_pid_1:given_name",
            false,
            List.of(
                    sdJwtAttributeMapper("sd-jwt-given_name", "urn:eudi:pid:1", "given_name", "firstName"),
                    sdJwtAttributeMapper("sd-jwt-family_name", "urn:eudi:pid:1", "family_name", "lastName"))),
    ISO_MDL(
            "mdoc_org_iso_18013_5_1_mDL:org\\.iso\\.18013\\.5\\.1.given_name",
            true,
            List.of(
                    mdocAttributeMapper(
                            "mdoc-given_name", "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "given_name", "firstName"),
                    mdocAttributeMapper(
                            "mdoc-family_name",
                            "org.iso.18013.5.1.mDL",
                            "org.iso.18013.5.1",
                            "family_name",
                            "lastName")));

    // The mDL issuer certificate of the conformance suite, trusted for mdoc scenarios.
    // Matches the document signer certificate in the suite's TestAppUtils/VciMdocUtils
    // (regenerated upstream 2026-08-03, valid until 2027-08-03).
    public static final String MDL_ISSUER_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICqzCCAlCgAwIBAgIULSsWFZgeqNOj8G3xd228JGgWiOUwCgYIKoZIzj0EAwIw
            gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
            BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
            BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjYw
            ODAzMTYxMjAxWhcNMjcwODAzMTYxMjAxWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
            BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
            DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
            ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
            lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
            48WXI8xhIphoNN7AejajgZcwgZQwHQYDVR0OBBYEFHhk9LVVH8Gt9ZgfxgyhSl92
            1XOhMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCEGA1UdEgQa
            MBiBFmNlcnRpZmljYXRpb25Ab2lkZi5vcmcwLAYDVR0fBCUwIzAhoB+gHYYbaHR0
            cDovL2V4YW1wbGUuY29tL215Y2EuY3JsMAoGCCqGSM49BAMCA0kAMEYCIQCB7MlD
            X8n8PDNoXfVpnHwQRfLC3bZzAs3zkGrHt7X2LwIhAJPQaIyvIb4LJIa0R4HQSvk0
            4OnujikkVHszNwSbyFlZ
            -----END CERTIFICATE-----
            """;

    private final String principalAttributes;
    private final boolean includeMdlIssuer;
    private final List<IdentityProviderMapperRepresentation> mappers;

    CredentialProfile(
            String principalAttributes, boolean includeMdlIssuer, List<IdentityProviderMapperRepresentation> mappers) {
        this.principalAttributes = principalAttributes;
        this.includeMdlIssuer = includeMdlIssuer;
        this.mappers = mappers;
    }

    /** The credential the subject is read from, and the claim of it that carries the subject. */
    public String principalAttributes() {
        return principalAttributes;
    }

    public boolean includeMdlIssuer() {
        return includeMdlIssuer;
    }

    public List<IdentityProviderMapperRepresentation> mappers() {
        return mappers;
    }

    private static IdentityProviderMapperRepresentation sdJwtAttributeMapper(
            String name, String vct, String claim, String userAttribute) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderMapper("oid4vp-sd-jwt-user-attribute-idp-mapper");
        mapper.setConfig(Map.of(
                "syncMode", "INHERIT",
                "credential.type", vct,
                "claim", claim,
                "user.attribute", userAttribute));
        return mapper;
    }

    private static IdentityProviderMapperRepresentation mdocAttributeMapper(
            String name, String doctype, String namespace, String element, String userAttribute) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderMapper("oid4vp-mdoc-user-attribute-idp-mapper");
        mapper.setConfig(Map.of(
                "syncMode", "INHERIT",
                "credential.type", doctype,
                "namespace", namespace,
                "claim", element,
                "user.attribute", userAttribute));
        return mapper;
    }
}
