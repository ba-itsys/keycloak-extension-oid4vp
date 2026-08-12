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
            "given_name",
            "given_name",
            false,
            List.of(
                    attributeMapper("sd-jwt-given_name", "dc+sd-jwt", "urn:eudi:pid:1", "given_name", "firstName"),
                    attributeMapper("sd-jwt-family_name", "dc+sd-jwt", "urn:eudi:pid:1", "family_name", "lastName"))),
    ISO_MDL(
            "given_name",
            "org.iso.18013.5.1/given_name",
            true,
            List.of(
                    attributeMapper(
                            "mdoc-given_name",
                            "mso_mdoc",
                            "org.iso.18013.5.1.mDL",
                            "org.iso.18013.5.1/given_name",
                            "firstName"),
                    attributeMapper(
                            "mdoc-family_name",
                            "mso_mdoc",
                            "org.iso.18013.5.1.mDL",
                            "org.iso.18013.5.1/family_name",
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

    private final String userMappingClaim;
    private final String userMappingClaimMdoc;
    private final boolean includeMdlIssuer;
    private final List<IdentityProviderMapperRepresentation> mappers;

    CredentialProfile(
            String userMappingClaim,
            String userMappingClaimMdoc,
            boolean includeMdlIssuer,
            List<IdentityProviderMapperRepresentation> mappers) {
        this.userMappingClaim = userMappingClaim;
        this.userMappingClaimMdoc = userMappingClaimMdoc;
        this.includeMdlIssuer = includeMdlIssuer;
        this.mappers = mappers;
    }

    public String userMappingClaim() {
        return userMappingClaim;
    }

    public String userMappingClaimMdoc() {
        return userMappingClaimMdoc;
    }

    public boolean includeMdlIssuer() {
        return includeMdlIssuer;
    }

    public List<IdentityProviderMapperRepresentation> mappers() {
        return mappers;
    }

    private static IdentityProviderMapperRepresentation attributeMapper(
            String name, String format, String credentialType, String claim, String userAttribute) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderMapper("oid4vp-user-attribute-mapper");
        mapper.setConfig(Map.of(
                "syncMode", "INHERIT",
                "credential.format", format,
                "credential.type", credentialType,
                "claim", claim,
                "user.attribute", userAttribute));
        return mapper;
    }
}
