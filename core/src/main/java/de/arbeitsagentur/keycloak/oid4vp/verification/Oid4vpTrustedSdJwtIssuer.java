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

import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TrustedIssuerKey;
import de.arbeitsagentur.keycloak.oid4vp.trust.X509CertificateChainValidator;
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
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.JwkParsingUtils;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;
import org.keycloak.util.KeyWrapperUtil;

/**
 * Keycloak SD-JWT issuer resolution strategy for this OID4VP extension, working on the trust
 * material resolved from the configured trust material identity providers.
 *
 * <p>Policy:
 * <ol>
 *   <li>Prefer x5c validation: a pinned trusted leaf or a PKIX path to the issuance trust anchors</li>
 *   <li>Then the issuer keys the credential's trust domain publishes, matched on iss and kid</li>
 *   <li>Finally, when that trust domain publishes no keys, fall back to JWT VC issuer metadata</li>
 * </ol>
 */
public class Oid4vpTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustedSdJwtIssuer.class);

    private final ResolvedTrust trust;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;

    public Oid4vpTrustedSdJwtIssuer(ResolvedTrust trust, JwtVcIssuerMetadataResolver issuerMetadataResolver) {
        this.trust = trust != null ? trust : ResolvedTrust.empty();
        this.issuerMetadataResolver = issuerMetadataResolver;
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
            if (requiresCertificateChain()) {
                throw new VerificationException(e.getMessage(), e);
            }
            LOG.debugf("x5c-based SD-JWT verification unavailable, trying fallback mechanisms: %s", e.getMessage());
        }

        // Issuer keys configured for this credential are the deliberate alternative to a chain, so
        // they take precedence over discovering keys from wherever the credential points to.
        List<SignatureVerifierContext> directVerifiers = directTrustVerifiers(issuerSignedJWT);
        if (!directVerifiers.isEmpty()) {
            LOG.debug("Using configured trusted issuer keys for signature verification");
            return directVerifiers;
        }

        if (issuerMetadataResolver != null && !trust.hasIssuerKeyTrust()) {
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

        if (x5cFailure != null) {
            throw new VerificationException(x5cFailure.getMessage(), x5cFailure);
        }
        throw new VerificationException("No trusted keys available for SD-JWT signature verification");
    }

    /**
     * Whether a certificate chain is mandatory for this credential. It is when the trust material
     * serving the credential can only validate chains. Pinned issuer certificates and published
     * issuer keys make a chainless credential a configured case, for example a credential signed
     * with a key whose certificate is trusted directly.
     */
    private boolean requiresCertificateChain() {
        return trust.hasCertificateChainAnchors() && !trust.hasChainlessIssuerTrust();
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiersFromX5c(IssuerSignedJWT issuerSignedJWT) {
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        List<String> x5c = header != null ? header.getX5c() : null;
        if (x5c == null || x5c.isEmpty()) {
            if (requiresCertificateChain()) {
                throw new IllegalStateException(
                        "The trust material of this credential mandates an x5c certificate chain, but the SD-JWT "
                                + "carries none");
            }
            return null;
        }
        if (!trust.hasX509Trust()) {
            // The trust domain of this credential identifies its issuer by key, so the presented
            // chain is not the route to validate it.
            return null;
        }
        try {
            List<X509Certificate> chain = X509CertificateChainValidator.decodeCertificateChain(x5c);
            PublicKey leafKey = trust.validateIssuerChain(chain);
            LOG.debug("SD-JWT x5c chain validated against trust material, using leaf certificate key");
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
        if (trust.issuanceTrust().isEmpty() && trust.directIssuerCertificates().isEmpty()) {
            return;
        }
        List<X509Certificate> chain = issuerKey.certificateChain();
        if (chain.isEmpty()) {
            return;
        }
        try {
            PublicKey validatedLeafKey = trust.validateIssuerChain(chain);
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

    /**
     * Verifiers for a credential that identifies its issuer key directly: pinned issuer
     * certificates, and the trusted issuer keys published for this credential's {@code iss} that
     * answer its {@code kid}. Binding the keys keeps trust domains apart, so a key published by one
     * issuer cannot verify a credential claiming to come from another.
     */
    private List<SignatureVerifierContext> directTrustVerifiers(IssuerSignedJWT issuerSignedJWT) {
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        String issuer = issuerSignedJWT.getPayload().path("iss").asText(null);
        String keyId = header != null ? header.getKeyId() : null;

        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (X509Certificate certificate : trust.issuerCertificatesFor(issuer)) {
            verifiers.add(toVerifierContext(certificate.getPublicKey()));
        }
        for (TrustedIssuerKey trustedIssuerKey : trust.issuerKeysFor(issuer, keyId)) {
            JWK jwk = trustedIssuerKey.jwk();
            try {
                verifiers.add(JwkParsingUtils.convertJwkToVerifierContext(jwk));
            } catch (Exception e) {
                LOG.debugf("Skipping unusable trusted issuer JWK '%s': %s", jwk.getKeyId(), e.getMessage());
            }
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
