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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import de.arbeitsagentur.keycloak.oid4vp.verification.JwtVcIssuerMetadataResolver.ResolvedIssuerKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/**
 * Verifies SD-JWT Verifiable Credentials presented in a VP token.
 *
 * <p>Performs issuer signature verification (via x5c chain or direct trust), key binding JWT
 * validation (audience, nonce, iat/exp), selective disclosure resolution, and claim extraction.
 * Uses Keycloak's built-in SD-JWT library ({@link SdJwtVP}).
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html">SD-JWT VC</a>
 */
public class SdJwtVerifier {

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);

    private final int clockSkewSeconds;
    private final int kbJwtMaxAgeSeconds;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;
    private final boolean strictX5cVerification;

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

            List<SignatureVerifierContext> verifiers = resolveIssuerVerifiers(sdJwtVP, trustedCertificates);

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

            sdJwtVP.verify(verifiers, issuerOpts, kbOptsBuilder.build());

            ObjectNode issuerPayload = sdJwtVP.getIssuerSignedJWT().getPayload();
            Map<String, Object> claims = extractDisclosedClaims(sdJwtVP);

            String issuer = stringValue(issuerPayload.get("iss"));
            String vct = stringValue(issuerPayload.get("vct"));

            return new SdJwtVerificationResult(claims, issuer, vct);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiers(
            SdJwtVP sdJwtVP, List<X509Certificate> trustedCertificates) {
        IllegalStateException x5cFailure = null;
        try {
            List<SignatureVerifierContext> x5cVerifiers = resolveIssuerVerifiersFromX5c(sdJwtVP, trustedCertificates);
            if (x5cVerifiers != null) {
                return x5cVerifiers;
            }
        } catch (IllegalStateException e) {
            x5cFailure = e;
            if (strictX5cVerification) {
                throw e;
            }
            LOG.debugf("x5c-based SD-JWT verification unavailable, trying fallback mechanisms: %s", e.getMessage());
        }

        if (issuerMetadataResolver != null) {
            try {
                ResolvedIssuerKey issuerKey = resolveIssuerKeyFromMetadata(sdJwtVP, trustedCertificates);
                LOG.debug("SD-JWT issuer key resolved via issuer metadata fallback");
                return List.of(toVerifierContext(issuerKey.publicKey()));
            } catch (IllegalStateException e) {
                LOG.debugf("Issuer metadata fallback failed: %s", e.getMessage());
                if (x5cFailure == null) {
                    x5cFailure = e;
                }
            }
        }

        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            if (x5cFailure != null) {
                throw x5cFailure;
            }
            throw new IllegalStateException("No trusted keys available for SD-JWT signature verification");
        }

        // Final fallback: try all trusted certificate keys directly (for self-signed or direct trust)
        LOG.debug("Using trusted certificate keys directly for signature verification");
        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (X509Certificate cert : trustedCertificates) {
            verifiers.add(toVerifierContext(cert.getPublicKey()));
        }
        return verifiers;
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiersFromX5c(
            SdJwtVP sdJwtVP, List<X509Certificate> trustedCertificates) {
        JWSHeader header = sdJwtVP.getIssuerSignedJWT().getJwsHeader();
        List<String> x5c = header != null ? header.getX5c() : null;
        if (x5c == null || x5c.isEmpty()) {
            if (strictX5cVerification) {
                throw new IllegalStateException("HAIP requires SD-JWT issuer certificates in the x5c header");
            }
            return null;
        }
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            throw new IllegalStateException("No trusted keys available for SD-JWT x5c signature verification");
        }
        try {
            PublicKey leafKey = X5cChainValidator.validateChain(x5c, trustedCertificates);
            LOG.debug("SD-JWT x5c chain validated against trust list, using leaf certificate key");
            return List.of(toVerifierContext(leafKey));
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT x5c validation failed: " + e.getMessage(), e);
        }
    }

    private ResolvedIssuerKey resolveIssuerKeyFromMetadata(SdJwtVP sdJwtVP, List<X509Certificate> trustedCertificates) {
        String issuer = stringValue(sdJwtVP.getIssuerSignedJWT().getPayload().get("iss"));
        JWSHeader header = sdJwtVP.getIssuerSignedJWT().getJwsHeader();
        String kid = header != null ? header.getKeyId() : null;

        ResolvedIssuerKey issuerKey = issuerMetadataResolver.resolveSigningKey(issuer, kid);
        validateResolvedKeyTrust(issuerKey, trustedCertificates);
        return issuerKey;
    }

    private String stringValue(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof JsonNode jsonNode) {
            return jsonNode.isTextual() ? jsonNode.textValue() : null;
        }
        return claim instanceof String string ? string : claim.toString();
    }

    private void validateResolvedKeyTrust(ResolvedIssuerKey issuerKey, List<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            return;
        }
        List<X509Certificate> chain = issuerKey.certificateChain();
        if (chain.isEmpty()) {
            return;
        }
        try {
            PublicKey validatedLeafKey = X5cChainValidator.validateCertChain(chain, trustedCertificates);
            if (!Arrays.equals(
                    validatedLeafKey.getEncoded(), issuerKey.publicKey().getEncoded())) {
                throw new IllegalStateException("Issuer metadata x5c leaf key does not match the resolved JWK");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Issuer metadata x5c validation failed: " + e.getMessage(), e);
        }
    }

    private SignatureVerifierContext toVerifierContext(PublicKey publicKey) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(publicKey);
        keyWrapper.setUse(KeyUse.SIG);

        String algo = publicKey.getAlgorithm();
        switch (algo) {
            case "EC" -> {
                keyWrapper.setType(KeyType.EC);
                if (publicKey instanceof ECPublicKey ecKey) {
                    keyWrapper.setCurve(resolveCurveName(ecKey));
                }
            }
            case "RSA" -> keyWrapper.setType(KeyType.RSA);
            case "EdDSA", "Ed25519", "Ed448" -> keyWrapper.setType(KeyType.OKP);
            default -> throw new IllegalStateException("Unsupported key type: " + algo);
        }

        return KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
    }

    private String resolveCurveName(ECPublicKey publicKey) {
        int fieldSize = publicKey.getParams().getCurve().getField().getFieldSize();
        return switch (fieldSize) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalStateException("Unsupported EC curve field size: " + fieldSize);
        };
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractDisclosedClaims(SdJwtVP sdJwtVP) {
        ObjectNode payload = sdJwtVP.getIssuerSignedJWT().getPayload();
        ObjectNode resolved = payload.deepCopy();

        Map<String, ArrayNode> disclosureMap = sdJwtVP.getClaims();
        resolveDisclosures(resolved, disclosureMap);
        cleanupSdClaims(resolved);

        return JsonSerialization.mapper.convertValue(resolved, Map.class);
    }

    private void resolveDisclosures(ObjectNode target, Map<String, ArrayNode> disclosureMap) {
        JsonNode sdArray = target.get("_sd");
        if (sdArray != null && sdArray.isArray()) {
            for (JsonNode digestNode : sdArray) {
                String digest = digestNode.asText();
                ArrayNode disclosure = disclosureMap.get(digest);
                if (disclosure != null && disclosure.size() >= 3) {
                    String claimName = disclosure.get(1).asText();
                    JsonNode claimValue = disclosure.get(2).deepCopy();
                    target.set(claimName, claimValue);

                    if (claimValue.isObject() && claimValue.has("_sd")) {
                        resolveDisclosures((ObjectNode) claimValue, disclosureMap);
                    }
                }
            }
        }

        Iterator<Map.Entry<String, JsonNode>> fields = target.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            if (field.getValue().isObject() && field.getValue().has("_sd") && !"_sd".equals(field.getKey())) {
                resolveDisclosures((ObjectNode) field.getValue(), disclosureMap);
            }
        }
    }

    private void cleanupSdClaims(ObjectNode node) {
        node.remove("_sd");
        node.remove("_sd_alg");
        node.remove("...");
        for (JsonNode child : node) {
            if (child.isObject()) {
                cleanupSdClaims((ObjectNode) child);
            }
        }
    }
}
