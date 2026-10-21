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
import de.arbeitsagentur.keycloak.oid4vp.trust.ResolvedTrust;
import de.arbeitsagentur.keycloak.oid4vp.trust.TrustedIssuerKey;
import de.arbeitsagentur.keycloak.oid4vp.util.FailureDetails;
import de.arbeitsagentur.keycloak.oid4vp.verification.JwtVcIssuerMetadataResolver.ResolvedIssuerKey;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.OID4VCConstants;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.X509CertificateChainValidator;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.JwkParsingUtils;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;
import org.keycloak.util.KeyWrapperUtil;

/**
 * Resolves the keys that verify an SD-JWT credential from the trust material configured for its
 * credential type, in this order:
 * <ol>
 *   <li>The x5c header, validated as a pinned trusted leaf or by a PKIX path to the issuer trust anchors</li>
 *   <li>Pinned certificates for the iss value, and published issuer keys matched on iss and kid</li>
 *   <li>JWT VC issuer metadata, only when no trust source is declared for the credential</li>
 * </ol>
 */
public class Oid4vpTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final int DNS_SUBJECT_ALT_NAME = 2;
    private static final int URI_SUBJECT_ALT_NAME = 6;

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustedSdJwtIssuer.class);
    private static final Set<X509Certificate> WARNED_INVALID_ISSUER_CERTIFICATES = ConcurrentHashMap.newKeySet();

    private final ResolvedTrust trust;
    private final boolean requireIssuerSanMatch;
    private final JwtVcIssuerMetadataResolver issuerMetadataResolver;

    public Oid4vpTrustedSdJwtIssuer(
            ResolvedTrust trust, JwtVcIssuerMetadataResolver issuerMetadataResolver, boolean requireIssuerSanMatch) {
        this.requireIssuerSanMatch = requireIssuerSanMatch;
        this.trust = trust != null ? trust : ResolvedTrust.empty();
        this.issuerMetadataResolver = issuerMetadataResolver;
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
        // Require iss because the allowedIssuers filter and issuer-specific trust material depend on it.
        JsonNode issuerClaim = issuerSignedJWT.getPayload().get(OID4VCConstants.CLAIM_NAME_ISSUER);
        if (issuerClaim == null
                || !issuerClaim.isTextual()
                || issuerClaim.asText().isBlank()) {
            throw new VerificationException("The SD-JWT VC carries no iss claim");
        }
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

        List<SignatureVerifierContext> directVerifiers = directTrustVerifiers(issuerSignedJWT);
        if (!directVerifiers.isEmpty()) {
            LOG.debug("Using configured trusted issuer keys for signature verification");
            return directVerifiers;
        }

        // Consult issuer metadata only when no trust source is configured for this credential. An
        // unreachable trust list then fails verification and never falls back to keys the issuer
        // advertises about itself.
        if (issuerMetadataResolver != null && !trust.hasIssuerKeyTrust() && !trust.hasDeclaredTrustSource()) {
            try {
                ResolvedIssuerKey issuerKey = resolveIssuerKeyFromMetadata(issuerSignedJWT);
                LOG.debug("SD-JWT issuer key resolved via issuer metadata fallback");
                return List.of(toVerifierContext(issuerKey.publicKey()));
            } catch (IllegalStateException e) {
                LOG.warnf(
                        "SD-JWT issuer key for iss=%s could not be resolved from issuer metadata: %s",
                        FailureDetails.singleLine(issuerClaim.asText()), FailureDetails.causeChain(e));
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
     * Requires a certificate chain when the trust material holds only CA certificates. Pinned
     * certificates and published issuer keys can verify a credential that carries no chain.
     */
    private boolean requiresCertificateChain() {
        return trust.hasCertificateChainAnchors() && !trust.hasChainlessIssuerTrust();
    }

    private List<SignatureVerifierContext> resolveIssuerVerifiersFromX5c(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
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
            return null;
        }
        String issuer = issuerSignedJWT
                .getPayload()
                .path(OID4VCConstants.CLAIM_NAME_ISSUER)
                .asText(null);
        List<X509Certificate> chain;
        PublicKey leafKey;
        try {
            chain = X509CertificateChainValidator.decodeCertificateChain(x5c);
            leafKey = trust.validateIssuerChain(chain, issuer);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "SD-JWT x5c validation failed for iss=" + issuer + ": " + FailureDetails.causeChain(e), e);
        }
        // A SAN mismatch must reject the credential. VerificationException lets that failure
        // reach the caller without trying another trusted key through the fallback path.
        if (requireIssuerSanMatch) {
            requireIssuerMatchesLeafSan(chain.get(0), issuer);
        }
        LOG.debug("SD-JWT x5c chain validated against trust material, using leaf certificate key");
        return List.of(toVerifierContext(leafKey));
    }

    private static void requireIssuerMatchesLeafSan(X509Certificate leaf, String issuer) throws VerificationException {
        Collection<List<?>> subjectAlternativeNames;
        try {
            subjectAlternativeNames = leaf.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new VerificationException("The leaf certificate's subject alternative names are unreadable", e);
        }
        if (subjectAlternativeNames != null) {
            String issuerHost = hostOfHttpsUri(issuer);
            for (List<?> entry : subjectAlternativeNames) {
                if (entry.size() < 2 || !(entry.get(1) instanceof String name)) {
                    continue;
                }
                int type = entry.get(0) instanceof Integer i ? i : -1;
                if (type == URI_SUBJECT_ALT_NAME && name.equals(issuer)) {
                    return;
                }
                if (type == DNS_SUBJECT_ALT_NAME && issuerHost != null && name.equalsIgnoreCase(issuerHost)) {
                    return;
                }
            }
        }
        throw new VerificationException("The credential issuer '" + issuer
                + "' does not match any subject alternative name of the validated leaf certificate");
    }

    private static String hostOfHttpsUri(String issuer) {
        try {
            URI uri = new URI(issuer);
            return "https".equalsIgnoreCase(uri.getScheme()) ? uri.getHost() : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private ResolvedIssuerKey resolveIssuerKeyFromMetadata(IssuerSignedJWT issuerSignedJWT) {
        String issuer = issuerSignedJWT
                .getPayload()
                .path(OID4VCConstants.CLAIM_NAME_ISSUER)
                .asText(null);
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        String kid = header != null ? header.getKeyId() : null;

        ResolvedIssuerKey issuerKey = issuerMetadataResolver.resolveSigningKey(issuer, kid);
        validateResolvedKeyTrust(issuerKey);
        return issuerKey;
    }

    private void validateResolvedKeyTrust(ResolvedIssuerKey issuerKey) {
        if (trust.issuerTrustAnchors().isEmpty()
                && trust.directIssuerCertificates().isEmpty()) {
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
     * Selects pinned certificates by the credential's iss value, and issuer keys by iss and kid. A
     * certificate or key configured for one issuer then cannot verify a credential that claims
     * another issuer.
     */
    private List<SignatureVerifierContext> directTrustVerifiers(IssuerSignedJWT issuerSignedJWT) {
        JWSHeader header = issuerSignedJWT.getJwsHeader();
        String issuer = issuerSignedJWT
                .getPayload()
                .path(OID4VCConstants.CLAIM_NAME_ISSUER)
                .asText(null);
        String keyId = header != null ? header.getKeyId() : null;

        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (X509Certificate certificate : trust.issuerCertificatesFor(issuer)) {
            try {
                certificate.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                if (WARNED_INVALID_ISSUER_CERTIFICATES.add(certificate)) {
                    LOG.warnf(
                            "Skipping trusted issuer certificate outside its validity: %s %s",
                            e.getMessage(), FailureDetails.certificate(certificate));
                }
                continue;
            }
            verifiers.add(toVerifierContext(certificate.getPublicKey()));
        }
        for (TrustedIssuerKey trustedIssuerKey : trust.issuerKeysFor(issuer, keyId)) {
            JWK jwk = trustedIssuerKey.jwk();
            try {
                verifiers.add(JwkParsingUtils.convertJwkToVerifierContext(jwk));
            } catch (Exception e) {
                LOG.warnf(
                        "Skipping unusable trusted issuer JWK '%s' for iss=%s: %s",
                        jwk.getKeyId(), FailureDetails.singleLine(issuer), FailureDetails.causeChain(e));
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
