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

// The credential format profile a verifier conformance scenario runs with
public enum CredentialProfile {
    SD_JWT_VC(
            "given_name",
            "given_name",
            """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:1"] },
                  "claims": [{ "path": ["given_name"] }, { "path": ["family_name"] }]
                }
              ],
              "credential_sets": [{ "options": [["pid_sd_jwt"]], "required": true }]
            }
            """,
            false,
            List.of(
                    attributeMapper("sd-jwt-given_name", "dc+sd-jwt", "pid", "given_name", "firstName"),
                    attributeMapper("sd-jwt-family_name", "dc+sd-jwt", "pid", "family_name", "lastName"))),
    ISO_MDL(
            "given_name",
            "org.iso.18013.5.1/given_name",
            """
            {
              "credentials": [
                {
                  "id": "pid_mdoc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                  "claims": [
                    { "path": ["org.iso.18013.5.1", "given_name"] },
                    { "path": ["org.iso.18013.5.1", "family_name"] }
                  ]
                }
              ],
              "credential_sets": [{ "options": [["pid_mdoc"]], "required": true }]
            }
            """,
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

    // The mDL issuer certificate of the conformance suite, trusted for mdoc scenarios
    public static final String MDL_ISSUER_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICqTCCAlCgAwIBAgIUEmctHgzxSGqk6Z8Eb+0s97VZdpowCgYIKoZIzj0EAwIw
            gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
            BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
            BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjUw
            NzMwMDc0NzIyWhcNMjYwNzMwMDc0NzIyWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
            BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
            DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
            ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
            lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
            48WXI8xhIphoNN7AejajgZcwgZQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
            Af8EBAMCAQYwIQYDVR0SBBowGIEWY2VydGlmaWNhdGlvbkBvaWRmLm9yZzAsBgNV
            HR8EJTAjMCGgH6AdhhtodHRwOi8vZXhhbXBsZS5jb20vbXljYS5jcmwwHQYDVR0O
            BBYEFHhk9LVVH8Gt9ZgfxgyhSl921XOhMAoGCCqGSM49BAMCA0cAMEQCICBxjCq9
            efAwMKREK+k0OXBtiQCbFD7QdpyH42LVYfdvAiAurlZwp9PtmQZzoSYDUvXpZM5v
            TvFLVc4ESGy3AtdC+g==
            -----END CERTIFICATE-----
            """;

    private final String userMappingClaim;
    private final String userMappingClaimMdoc;
    private final String dcqlQuery;
    private final boolean includeMdlIssuer;
    private final List<IdentityProviderMapperRepresentation> mappers;

    CredentialProfile(
            String userMappingClaim,
            String userMappingClaimMdoc,
            String dcqlQuery,
            boolean includeMdlIssuer,
            List<IdentityProviderMapperRepresentation> mappers) {
        this.userMappingClaim = userMappingClaim;
        this.userMappingClaimMdoc = userMappingClaimMdoc;
        this.dcqlQuery = dcqlQuery;
        this.includeMdlIssuer = includeMdlIssuer;
        this.mappers = mappers;
    }

    public String userMappingClaim() {
        return userMappingClaim;
    }

    public String userMappingClaimMdoc() {
        return userMappingClaimMdoc;
    }

    public String dcqlQuery() {
        return dcqlQuery;
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
