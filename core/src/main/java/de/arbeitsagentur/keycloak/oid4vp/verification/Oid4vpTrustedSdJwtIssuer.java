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

import de.arbeitsagentur.keycloak.oid4vp.verification.JwtVcIssuerMetadataResolver.ResolvedIssuerKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;
import org.keycloak.util.KeyWrapperUtil;

/**
 * Keycloak SD-JWT issuer resolution strategy for this OID4VP extension.
 *
 * <p>Policy:
 * <ol>
 *   <li>Prefer x5c validation against trusted certificates</li>
 *   <li>When HAIP is not enforced, fall back to JWT VC issuer metadata</li>
 *   <li>Finally, try trusted certificates directly as issuer keys</li>
 * </ol>
 */
public class Oid4vpTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustedSdJwtIssuer.class);

    private final List<X509Certificate> trustedCertificates;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;
    private final boolean strictX5cVerification;

    public Oid4vpTrustedSdJwtIssuer(
            List<X509Certificate> trustedCertificates,
            JwtVcIssuerMetadataResolver issuerMetadataResolver,
            boolean strictX5cVerification) {
        this.trustedCertificates = trustedCertificates != null ? List.copyOf(trustedCertificates) : List.of();
        this.issuerMetadataResolver = issuerMetadataResolver;
        this.strictX5cVerification = strictX5cVerification;
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
        IllegalStateException x5cFailure = null;
        try {
            List<SignatureVerifierContext> x5cVerifiers = resolveIssuerVerifiersFromX5c(issuerSignedJWT);
            if (x5cVerifiers != null) {
                return x5cVerifiers;
            }
        } catch (IllegalStateException e) {
            x5cFailure = e;
            if (strictX5cVerification) {
                throw new VerificationException(e.getMessage(), e);
            }
            LOG.debugf("x5c-based SD-JWT verification unavailable, trying fallback mechanisms: %s", e.getMessage());
        }

        if (issuerMetadataResolver != null) {
            try {
                ResolvedIssuerKey issuerKey = resolveIssuerKeyFromMetadata(issuerSignedJWT);
                LOG.debug("SD-JWT issuer key resolved via issuer metadata fallback");
                return List.of(toVerifierContext(issuerKey.publicKey()));
            } catch (IllegalStateException e) {
                LOG.debugf("Issuer metadata fallback failed: %s", e.getMessage());
                if (x5cFailure == null) {
                    x5cFailure = e;
                }
            }
        }

        if (trustedCertificates.isEmpty()) {
            if (x5cFailure != null) {
                throw new VerificationException(x5cFailure.getMessage(), x5cFailure);
            }
            throw new VerificationException("No trusted keys available for SD-JWT signature verification");
        }

        LOG.debug("Using trusted certificate keys directly for signature verification");
        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (X509Certificate cert : trustedCertificates) {
            verifiers.add(toVerifierContext(cert.getPublicKey()));
        }
        return verifiers;
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiersFromX5c(IssuerSignedJWT issuerSignedJWT) {
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        List<String> x5c = header != null ? header.getX5c() : null;
        if (x5c == null || x5c.isEmpty()) {
            if (strictX5cVerification) {
                throw new IllegalStateException("HAIP requires SD-JWT issuer certificates in the x5c header");
            }
            return null;
        }
        if (trustedCertificates.isEmpty()) {
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

    private ResolvedIssuerKey resolveIssuerKeyFromMetadata(IssuerSignedJWT issuerSignedJWT) {
        String issuer = issuerSignedJWT.getPayload().path("iss").asText(null);
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        String kid = header != null ? header.getKeyId() : null;

        ResolvedIssuerKey issuerKey = issuerMetadataResolver.resolveSigningKey(issuer, kid);
        validateResolvedKeyTrust(issuerKey);
        return issuerKey;
    }

    private void validateResolvedKeyTrust(ResolvedIssuerKey issuerKey) {
        if (trustedCertificates.isEmpty()) {
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
}
