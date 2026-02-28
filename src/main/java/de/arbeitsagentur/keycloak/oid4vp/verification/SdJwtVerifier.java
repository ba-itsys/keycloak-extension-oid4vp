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
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

public class SdJwtVerifier {

    private static final Logger LOG = Logger.getLogger(SdJwtVerifier.class);
    private static final int CLOCK_SKEW_SECONDS = 60;
    private static final int KB_JWT_MAX_AGE_SECONDS = 300;

    public boolean isSdJwt(String token) {
        return token != null && token.contains("~");
    }

    @SuppressWarnings("unchecked")
    public SdJwtVerificationResult verify(
            String sdJwt, String expectedAudience, String expectedNonce, List<PublicKey> trustedKeys) {

        try {
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);

            List<SignatureVerifierContext> verifiers = resolveIssuerVerifiers(trustedKeys);

            IssuerSignedJwtVerificationOpts issuerOpts = IssuerSignedJwtVerificationOpts.builder()
                    .withClockSkew(CLOCK_SKEW_SECONDS)
                    .withExpCheck(true)
                    .withNbfCheck(true)
                    .build();

            boolean hasKbJwt = sdJwtVP.getKeyBindingJWT().isPresent();
            KeyBindingJwtVerificationOpts.Builder kbBuilder = KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(hasKbJwt)
                    .withIatCheck(KB_JWT_MAX_AGE_SECONDS)
                    .withExpCheck(true)
                    .withNbfCheck(true)
                    .withClockSkew(CLOCK_SKEW_SECONDS);
            if (hasKbJwt) {
                kbBuilder.withAudCheck(expectedAudience);
                kbBuilder.withNonceCheck(expectedNonce);
            }

            sdJwtVP.verify(verifiers, issuerOpts, kbBuilder.build());

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

    private List<SignatureVerifierContext> resolveIssuerVerifiers(List<PublicKey> trustedKeys) {
        if (trustedKeys == null || trustedKeys.isEmpty()) {
            throw new IllegalStateException("No trusted keys available for SD-JWT signature verification");
        }

        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (PublicKey key : trustedKeys) {
            verifiers.add(toVerifierContext(key));
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
