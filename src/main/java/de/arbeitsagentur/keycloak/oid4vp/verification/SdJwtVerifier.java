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
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
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

            String issuer = claims.containsKey("iss") ? claims.get("iss").toString() : null;
            String vct = claims.containsKey("vct") ? claims.get("vct").toString() : null;

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
                PublicKey leafKey = validateX5cChain(x5c, trustedCertificates);
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

    /**
     * Validates an x5c certificate chain against trusted CA certificates.
     * Returns the leaf certificate's public key if the chain is trusted.
     */
    private PublicKey validateX5cChain(List<String> x5c, List<X509Certificate> trustedCertificates) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Parse x5c chain: first element is the leaf certificate
        List<X509Certificate> chain = new ArrayList<>();
        for (String certB64 : x5c) {
            byte[] certDer = Base64.getDecoder().decode(certB64);
            chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
        }

        if (chain.isEmpty()) {
            throw new IllegalStateException("Empty x5c chain");
        }

        X509Certificate leaf = chain.get(0);
        LOG.debugf(
                "SD-JWT x5c leaf certificate: %s",
                leaf.getSubjectX500Principal().getName());

        // Walk up the chain: each cert should be signed by the next one
        for (int i = 0; i < chain.size() - 1; i++) {
            chain.get(i).verify(chain.get(i + 1).getPublicKey());
        }

        // The last cert in the chain (or the leaf if chain has only 1 cert) must be
        // signed by one of the trusted certificates
        X509Certificate topOfChain = chain.get(chain.size() - 1);
        for (X509Certificate trusted : trustedCertificates) {
            try {
                topOfChain.verify(trusted.getPublicKey());
                LOG.debugf(
                        "x5c chain anchored by trusted certificate: %s",
                        trusted.getSubjectX500Principal().getName());
                return leaf.getPublicKey();
            } catch (Exception ignored) {
                // Try next trusted certificate
            }
        }

        throw new IllegalStateException("x5c chain not anchored by any trusted certificate");
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
