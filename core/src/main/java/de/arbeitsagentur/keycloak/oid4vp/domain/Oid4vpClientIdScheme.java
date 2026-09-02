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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import de.arbeitsagentur.keycloak.oid4vp.verification.X5cChainValidator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.utils.StringUtil;

/** The OID4VP {@code client_id_scheme} values and their client id prefixes. */
public enum Oid4vpClientIdScheme {
    PLAIN("plain", ""),
    X509_SAN_DNS("x509_san_dns", "x509_san_dns:"),
    X509_HASH("x509_hash", "x509_hash:");

    private static final int DNS_SUBJECT_ALT_NAME = 2;
    private static final Logger LOG = Logger.getLogger(Oid4vpClientIdScheme.class);
    private static final Set<String> WARNED_VERIFIER_CERTIFICATE_PEMS = ConcurrentHashMap.newKeySet();

    private final String configValue;
    private final String prefix;

    Oid4vpClientIdScheme(String configValue, String prefix) {
        this.configValue = configValue;
        this.prefix = prefix;
    }

    public String configValue() {
        return configValue;
    }

    public String prefix() {
        return prefix;
    }

    public String formatValue(String value) {
        return prefix + value;
    }

    public boolean isCertificateBound() {
        return this != PLAIN;
    }

    /**
     * Validates the configured verifier certificate for this scheme. The chain travels in the
     * request object and the client id is derived from its leaf, so it has to be coherent and
     * currently valid. Whether a wallet accepts the certificate is the wallet's own decision
     * against its relying party trust list, so a configuration a wallet is likely to reject is
     * only warned about here.
     */
    public void validateCertificateBinding(String pemCertificate) {
        if (!isCertificateBound()) {
            return;
        }
        if (StringUtil.isBlank(pemCertificate)) {
            throw new IllegalStateException("Certificate-bound client_id_scheme requires an X.509 certificate");
        }
        validateEmittedVerifierCertificateChain(pemCertificate);
    }

    public String computeClientId(String clientId, String pemCertificate) {
        if (!isCertificateBound() || StringUtil.isBlank(pemCertificate)) {
            return clientId;
        }
        return switch (this) {
            case PLAIN -> clientId;
            case X509_SAN_DNS -> formatValue(extractDnsSubjectAlternativeName(pemCertificate));
            case X509_HASH -> formatValue(computeCertificateHash(pemCertificate));
        };
    }

    /**
     * Resolves the configured scheme, defaulting to the certificate bound scheme wallets expect.
     * An unrecognized value can only come from scripted or imported configuration, and falling
     * back to the default silently changes the emitted client id, so it is warned about.
     */
    public static Oid4vpClientIdScheme resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return X509_HASH;
        }
        for (Oid4vpClientIdScheme scheme : values()) {
            if (scheme.configValue.equalsIgnoreCase(rawValue)) {
                return scheme;
            }
        }
        LOG.warnf("Unknown client_id_scheme '%s' configured; using %s", rawValue, X509_HASH.configValue);
        return X509_HASH;
    }

    private static String extractDnsSubjectAlternativeName(String pemCertificate) {
        try {
            X509Certificate certificate = decodeFirstCertificate(pemCertificate);
            Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames();
            if (subjectAlternativeNames != null) {
                for (List<?> subjectAlternativeName : subjectAlternativeNames) {
                    if (subjectAlternativeName.size() >= 2
                            && Integer.valueOf(DNS_SUBJECT_ALT_NAME).equals(subjectAlternativeName.get(0))) {
                        return subjectAlternativeName.get(1).toString();
                    }
                }
            }
            throw new IllegalStateException("No DNS SAN found in certificate");
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract DNS SAN from certificate", e);
        }
    }

    private static String computeCertificateHash(String pemCertificate) {
        try {
            X509Certificate certificate = decodeFirstCertificate(pemCertificate);
            return Base64Url.encode(HashUtils.hash(JavaAlgorithm.SHA256, certificate.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute certificate hash", e);
        }
    }

    private static X509Certificate decodeFirstCertificate(String pemCertificate) {
        List<X509Certificate> certificates = parseCertificateChain(pemCertificate);
        if (certificates.isEmpty()) {
            throw new IllegalStateException("No certificates found in PEM");
        }
        return certificates.get(0);
    }

    private static void validateEmittedVerifierCertificateChain(String pemCertificate) {
        try {
            List<X509Certificate> certificates = parseCertificateChain(pemCertificate);
            X5cChainValidator.validateEmittedVerifierChain(certificates);
            warnAboutLikelyWalletRejectionOnce(pemCertificate, certificates);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to validate verifier certificate", e);
        }
    }

    /**
     * Warns about a configuration that wallets following the high assurance profile reject,
     * without failing it. That profile requires a CA issued verifier certificate, but a closed
     * deployment may run against wallets that accept a self-signed one.
     */
    private static void warnAboutLikelyWalletRejectionOnce(String pemCertificate, List<X509Certificate> certificates) {
        X509Certificate leaf = certificates.get(0);
        String problem = null;
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            problem = "the verifier certificate is self-signed";
        } else if (certificates.size() == 1) {
            problem = "only the leaf certificate is configured, so its issuing CA cannot be confirmed here";
        } else if (leaf.getBasicConstraints() >= 0) {
            problem = "the verifier leaf certificate is a CA certificate";
        }
        if (problem != null && WARNED_VERIFIER_CERTIFICATE_PEMS.add(computePemHash(pemCertificate))) {
            LOG.warnf(
                    "Verifier certificate configuration: %s. Wallets following the high assurance profile require a "
                            + "CA-issued verifier certificate and are likely to reject the authorization request.",
                    problem);
        }
    }

    private static String computePemHash(String pemCertificate) {
        try {
            byte[] digest = MessageDigest.getInstance(JavaAlgorithm.SHA256)
                    .digest(pemCertificate.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            return pemCertificate;
        }
    }

    private static List<X509Certificate> parseCertificateChain(String pemCertificate) {
        List<X509Certificate> certificates = new ArrayList<>();
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        int offset = 0;
        while (offset >= 0 && offset < pemCertificate.length()) {
            int start = pemCertificate.indexOf(begin, offset);
            if (start < 0) {
                break;
            }
            int stop = pemCertificate.indexOf(end, start);
            if (stop < 0) {
                throw new IllegalStateException("Incomplete CERTIFICATE block in PEM");
            }
            certificates.add(PemUtils.decodeCertificate(pemCertificate.substring(start, stop + end.length())));
            offset = stop + end.length();
        }
        return certificates;
    }
}
