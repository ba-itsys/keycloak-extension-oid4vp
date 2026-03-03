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
import com.nimbusds.jose.jwk.Curve;
import de.arbeitsagentur.keycloak.oid4vp.domain.SdJwtVerificationResult;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
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

    public SdJwtVerifier(int clockSkewSeconds, int kbJwtMaxAgeSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
        this.kbJwtMaxAgeSeconds = kbJwtMaxAgeSeconds;
    }

    public boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    @SuppressWarnings("unchecked")
    /**
     * Verifies an SD-JWT VP: validates issuer signature, key binding, and extracts disclosed claims.
     *
     * @param sdJwt the compact SD-JWT string (issuer JWT + disclosures + optional KB-JWT, tilde-separated)
     * @param expectedAudience the expected {@code aud} claim in the key binding JWT
     * @param expectedNonce the expected {@code nonce} claim in the key binding JWT
     * @param trustedCertificates trusted CA certificates for issuer signature verification
     */
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

            Map<String, Object> claims = extractDisclosedClaims(sdJwtVP);

            Object issuerObj = claims.get("iss");
            String issuer = issuerObj != null ? issuerObj.toString() : null;
            Object vctObj = claims.get("vct");
            String vct = vctObj != null ? vctObj.toString() : null;

            return new SdJwtVerificationResult(claims, issuer, vct);
        } catch (VerificationException e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("SD-JWT verification failed: " + e.getMessage(), e);
        }
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiers(
            SdJwtVP sdJwtVP, List<X509Certificate> trustedCertificates) {
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            throw new IllegalStateException("No trusted keys available for SD-JWT signature verification");
        }

        // Try x5c chain validation: extract the leaf cert from the SD-JWT header,
        // verify the chain against trusted CA certificates, then use the leaf key.
        JWSHeader header = sdJwtVP.getIssuerSignedJWT().getJwsHeader();
        List<String> x5c = header != null ? header.getX5c() : null;
        if (x5c != null && !x5c.isEmpty()) {
            try {
                PublicKey leafKey = X5cChainValidator.validateChain(x5c, trustedCertificates);
                LOG.debug("SD-JWT x5c chain validated against trust list, using leaf certificate key");
                return List.of(toVerifierContext(leafKey));
            } catch (Exception e) {
                LOG.debugf("x5c chain validation failed: %s", e.getMessage());
            }
        }

        // Fallback: try all trusted certificate keys directly (for self-signed or direct trust)
        LOG.debug("Using trusted certificate keys directly for signature verification");
        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (X509Certificate cert : trustedCertificates) {
            verifiers.add(toVerifierContext(cert.getPublicKey()));
        }
        return verifiers;
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
                    keyWrapper.setCurve(
                            Curve.forECParameterSpec(ecKey.getParams()).getName());
                }
            }
            case "RSA" -> keyWrapper.setType(KeyType.RSA);
            case "EdDSA", "Ed25519", "Ed448" -> keyWrapper.setType(KeyType.OKP);
            default -> throw new IllegalStateException("Unsupported key type: " + algo);
        }

        return KeyWrapperUtil.createSignatureVerifierContext(keyWrapper);
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
