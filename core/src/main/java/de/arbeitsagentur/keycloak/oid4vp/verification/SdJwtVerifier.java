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
import org.jboss.logging.Logger;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Verifies SD-JWT Verifiable Credentials presented in a VP token. This is a thin facade over
 * Keycloak's SD-JWT consumer APIs: Keycloak runs the presentation verification flow, while the
 * extension keeps its own issuer trust policy and the orchestration after verification.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901, Selective Disclosure for JSON Web Tokens</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13">draft-ietf-oauth-sd-jwt-vc-13, SD-JWT VC</a>
 */
public class SdJwtVerifier {

    private static final String VCT_CLAIM = "vct";

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);

    private final int clockSkewSeconds;
    private final int kbJwtMaxAgeSeconds;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;
    private final SdJwtPresentationConsumer presentationConsumer = new SdJwtPresentationConsumer();

    public SdJwtVerifier(int clockSkewSeconds, int kbJwtMaxAgeSeconds) {
        this(clockSkewSeconds, kbJwtMaxAgeSeconds, null);
    }

    public SdJwtVerifier(
            int clockSkewSeconds, int kbJwtMaxAgeSeconds, JwtVcIssuerMetadataResolver issuerMetadataResolver) {
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
            JsonNode vct = payload.get(VCT_CLAIM);
            if (vct == null || !vct.isTextual()) {
                return null;
            }
            return new ClaimedTypes(vct.asText(), CredentialTypeHierarchy.alsoKnownAsTypes(payload));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verifies an SD-JWT VP, checking the issuer signature and the key binding and extracting the
     * disclosed claims. The expected audience and nonce are matched against the key binding JWT.
     */
    @SuppressWarnings("unchecked")
    public SdJwtVerificationResult verify(
            String sdJwt, String expectedAudience, String expectedNonce, ResolvedTrust trust) {

        try {
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);
            Oid4vpPresentationRequirements requirements = new Oid4vpPresentationRequirements();

            // The ClaimVerifier.Builder constructor adds an IatLifetimeCheck with the KB-JWT default
            // maxAge of 300 seconds to every builder, including the issuer options. It is removed for
            // issuer JWTs because credentials can be arbitrarily old, and their expiration is judged
            // by the exp claim.
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

            presentationConsumer.verifySdJwtPresentation(
                    sdJwtVP,
                    requirements,
                    List.of(new Oid4vpTrustedSdJwtIssuer(trust, issuerMetadataResolver)),
                    issuerOpts,
                    kbOptsBuilder.build());

            return requirements.getVerifiedResult();
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }
}
