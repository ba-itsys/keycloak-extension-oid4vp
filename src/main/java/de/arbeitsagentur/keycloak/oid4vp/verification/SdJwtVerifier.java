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

import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Verifies SD-JWT Verifiable Credentials presented in a VP token.
 *
 * <p>This is a thin facade over Keycloak's SD-JWT consumer APIs. The extension keeps its custom
 * issuer-trust policy and post-verification orchestration, but relies on Keycloak for the actual
 * presentation verification flow.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html">SD-JWT VC</a>
 */
public class SdJwtVerifier {

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);

    private final int clockSkewSeconds;
    private final int kbJwtMaxAgeSeconds;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;
    private final boolean strictX5cVerification;
    private final SdJwtPresentationConsumer presentationConsumer = new SdJwtPresentationConsumer();

    public SdJwtVerifier(int clockSkewSeconds, int kbJwtMaxAgeSeconds) {
        this(clockSkewSeconds, kbJwtMaxAgeSeconds, null, false);
    }

    public SdJwtVerifier(
            int clockSkewSeconds,
            int kbJwtMaxAgeSeconds,
            JwtVcIssuerMetadataResolver issuerMetadataResolver,
            boolean strictX5cVerification) {
        this.clockSkewSeconds = clockSkewSeconds;
        this.kbJwtMaxAgeSeconds = kbJwtMaxAgeSeconds;
        this.issuerMetadataResolver = issuerMetadataResolver;
        this.strictX5cVerification = strictX5cVerification;
    }

    public boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    /**
     * Verifies an SD-JWT VP: validates issuer signature, key binding, and extracts disclosed claims.
     *
     * @param sdJwt the compact SD-JWT string (issuer JWT + disclosures + optional KB-JWT, tilde-separated)
     * @param expectedAudience the expected {@code aud} claim in the key binding JWT
     * @param expectedNonce the expected {@code nonce} claim in the key binding JWT
     * @param trustedCertificates trusted CA certificates for issuer signature verification
     */
    @SuppressWarnings("unchecked")
    public SdJwtVerificationResult verify(
            String sdJwt, String expectedAudience, String expectedNonce, List<X509Certificate> trustedCertificates) {

        try {
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);
            Oid4vpPresentationRequirements requirements = new Oid4vpPresentationRequirements();

            // The ClaimVerifier.Builder constructor adds an IatLifetimeCheck with the KB-JWT default
            // maxAge (300s) to ALL builders, including issuer opts. We must remove it for issuer JWTs
            // since credentials can be arbitrarily old — expiration is handled by the exp claim.
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
                    List.of(new Oid4vpTrustedSdJwtIssuer(
                            trustedCertificates, issuerMetadataResolver, strictX5cVerification)),
                    issuerOpts,
                    kbOptsBuilder.build());

            return requirements.getVerifiedResult();
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }
}
