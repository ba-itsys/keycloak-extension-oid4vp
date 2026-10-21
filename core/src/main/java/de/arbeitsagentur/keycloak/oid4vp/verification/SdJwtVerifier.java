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
package de.arbeitsagentur.keycloak.oid4vp.verification;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.ClaimedTypes;
import de.arbeitsagentur.keycloak.oid4vp.domain.CredentialTypeHierarchy;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OID4VCConstants;
import org.keycloak.VCFormat;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sdjwt.vp.SdJwtVpVerificationResult;
import org.keycloak.util.JsonSerialization;

/**
 * Verifies SD-JWT Verifiable Credentials presented in a VP token. Keycloak's SD-JWT consumer runs
 * the presentation verification. The extension supplies its own issuer trust policy.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901, Selective Disclosure for JSON Web Tokens</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13">draft-ietf-oauth-sd-jwt-vc-13, SD-JWT VC</a>
 */
public class SdJwtVerifier {

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);
    private static final String MEDIA_TYPE_PREFIX = "application/";
    private static final String TRANSITIONAL_SD_JWT_VC_TYPE = "vc+sd-jwt";

    private final int clockSkewSeconds;
    private final int kbJwtMaxAgeSeconds;
    private final boolean requireIssuerSanMatch;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;
    private final SdJwtPresentationConsumer presentationConsumer = new SdJwtPresentationConsumer();

    public SdJwtVerifier(int clockSkewSeconds, int kbJwtMaxAgeSeconds) {
        this(clockSkewSeconds, kbJwtMaxAgeSeconds, null);
    }

    public SdJwtVerifier(
            int clockSkewSeconds, int kbJwtMaxAgeSeconds, JwtVcIssuerMetadataResolver issuerMetadataResolver) {
        this(clockSkewSeconds, kbJwtMaxAgeSeconds, issuerMetadataResolver, false);
    }

    public SdJwtVerifier(
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds,
            JwtVcIssuerMetadataResolver issuerMetadataResolver,
            boolean requireIssuerSanMatch) {
        this.requireIssuerSanMatch = requireIssuerSanMatch;
        this.clockSkewSeconds = clockSkewSeconds;
        this.kbJwtMaxAgeSeconds = kbJwtMaxAgeSeconds;
        this.issuerMetadataResolver = issuerMetadataResolver;
    }

    public boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    /**
     * Reads the {@code vct} and {@code aka_vcts} of the issuer-signed JWT without verifying
     * anything, so the caller can tell which requested type a presentation answers before it picks
     * the trust material. Returns null when the token does not parse or carries no {@code vct}.
     */
    public ClaimedTypes peekTypes(String sdJwt) {
        try {
            JsonNode payload = SdJwtVP.of(sdJwt).getIssuerSignedJWT().getPayload();
            JsonNode vct = payload.get(OID4VCConstants.CLAIM_NAME_VCT);
            if (vct == null || !vct.isTextual()) {
                return null;
            }
            return new ClaimedTypes(vct.asText(), CredentialTypeHierarchy.alsoKnownAsTypes(payload));
        } catch (Exception e) {
            return null;
        }
    }

    // Requires a key binding JWT only when both the expected audience and nonce are given.
    @SuppressWarnings("unchecked")
    public SdJwtVerificationResult verify(
            String sdJwt, String expectedAudience, String expectedNonce, ResolvedTrust trust) {

        try {
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);
            String type = sdJwtVP.getIssuerSignedJWT().getJwsHeader().getType();
            if (!isSdJwtVcType(type)) {
                throw new IllegalStateException(
                        "The issuer-signed JWT has typ " + type + " instead of " + VCFormat.SD_JWT_VC);
            }

            // ClaimVerifier.Builder adds an IatLifetimeCheck with the KB-JWT default maxAge of 300 seconds
            // to every builder, including the issuer options. Remove it for the issuer JWT, because a
            // credential can be arbitrarily old and its exp claim decides when it expires.
            IssuerSignedJwtVerificationOpts issuerOpts = IssuerSignedJwtVerificationOpts.builder()
                    .withClockSkew(clockSkewSeconds)
                    .withIatCheck(null)
                    .withExpCheck(true)
                    .withNbfCheck(true)
                    .build();

            boolean hasKbParams = expectedAudience != null && expectedNonce != null;
            KeyBindingJwtVerificationOpts.Builder kbOptsBuilder = KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(hasKbParams)
                    .withClockSkew(clockSkewSeconds)
                    .withIatCheck(kbJwtMaxAgeSeconds)
                    .withExpCheck(true)
                    .withNbfCheck(true);
            if (hasKbParams) {
                kbOptsBuilder.withAudCheck(expectedAudience).withNonceCheck(expectedNonce);
            }

            SdJwtVpVerificationResult result = presentationConsumer.verifySdJwtPresentation(
                    sdJwtVP,
                    disclosedPayload -> {},
                    List.of(new Oid4vpTrustedSdJwtIssuer(trust, issuerMetadataResolver, requireIssuerSanMatch)),
                    issuerOpts,
                    kbOptsBuilder.build());

            JsonNode claims = result.getClaims();
            return new SdJwtVerificationResult(
                    JsonSerialization.mapper.convertValue(claims, Map.class),
                    result.getIssuer(),
                    result.getCredentialType(),
                    CredentialTypeHierarchy.alsoKnownAsTypes(claims));
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Accepts {@code dc+sd-jwt} and the earlier {@code vc+sd-jwt}, which draft-ietf-oauth-sd-jwt-vc-13
     * section 3.2.1 recommends accepting for a transitional period. A typ is a media type, so it
     * matches case-insensitively and with or without the {@code application/} prefix (RFC 7515
     * section 4.1.9).
     */
    private static boolean isSdJwtVcType(String type) {
        if (type == null) {
            return false;
        }
        String subtype = type.regionMatches(true, 0, MEDIA_TYPE_PREFIX, 0, MEDIA_TYPE_PREFIX.length())
                ? type.substring(MEDIA_TYPE_PREFIX.length())
                : type;
        return subtype.equalsIgnoreCase(VCFormat.SD_JWT_VC) || subtype.equalsIgnoreCase(TRANSITIONAL_SD_JWT_VC_TYPE);
    }
}
