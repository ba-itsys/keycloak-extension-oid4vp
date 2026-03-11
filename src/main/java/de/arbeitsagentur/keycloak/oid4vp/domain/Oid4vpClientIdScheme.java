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
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.utils.StringUtil;

/** Models the OID4VP {@code client_id_scheme} values and their client ID prefixes. */
public enum Oid4vpClientIdScheme {
    PLAIN("plain", ""),
    X509_SAN_DNS("x509_san_dns", "x509_san_dns:"),
    X509_HASH("x509_hash", "x509_hash:");

    private static final int DNS_SUBJECT_ALT_NAME = 2;
    private static final Logger LOG = Logger.getLogger(Oid4vpClientIdScheme.class);
    private static final Set<String> WARNED_SINGLE_LEAF_PEMS = ConcurrentHashMap.newKeySet();

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

    public void validateCertificateBinding(String pemCertificate, boolean enforceHaip) {
        if (!isCertificateBound()) {
            return;
        }
        if (StringUtil.isBlank(pemCertificate)) {
            throw new IllegalStateException("Certificate-bound client_id_scheme requires an X.509 certificate");
        }
        if (enforceHaip) {
            validateHaipVerifierCertificateChain(pemCertificate);
        }
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

    public static Oid4vpClientIdScheme resolve(String rawValue, boolean enforceHaip) {
        if (enforceHaip) {
            return X509_HASH;
        }
        return resolve(rawValue);
    }

    public static Oid4vpClientIdScheme resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return X509_SAN_DNS;
        }
        for (Oid4vpClientIdScheme scheme : values()) {
            if (scheme.configValue.equalsIgnoreCase(rawValue)) {
                return scheme;
            }
        }
        return X509_SAN_DNS;
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
            byte[] digest = MessageDigest.getInstance(JavaAlgorithm.SHA256).digest(certificate.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
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

    private static void validateHaipVerifierCertificateChain(String pemCertificate) {
        try {
            List<X509Certificate> certificates = parseCertificateChain(pemCertificate);
            if (certificates.size() == 1) {
                validateSingleHaipLeaf(certificates.get(0));
                warnSingleLeafAssumptionOnce(pemCertificate);
                return;
            }
            X5cChainValidator.validateConfiguredVerifierChain(certificates);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to validate verifier certificate", e);
        }
    }

    private static void validateSingleHaipLeaf(X509Certificate certificate) {
        if (certificate.getBasicConstraints() >= 0) {
            throw new IllegalStateException("HAIP verifier leaf certificate must not be a CA certificate");
        }
        if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            throw new IllegalStateException("HAIP requires x509_hash verifier certificates to be CA-issued");
        }
    }

    private static void warnSingleLeafAssumptionOnce(String pemCertificate) {
        String warningKey = computePemHash(pemCertificate);
        if (WARNED_SINGLE_LEAF_PEMS.add(warningKey)) {
            LOG.warn("HAIP verifier certificate configuration contains only the leaf certificate. "
                    + "Startup validation cannot confirm the issuing CA; relying on external trust lists at runtime.");
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
