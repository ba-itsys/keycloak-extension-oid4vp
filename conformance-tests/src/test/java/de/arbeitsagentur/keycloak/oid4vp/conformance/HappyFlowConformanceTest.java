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
package de.arbeitsagentur.keycloak.oid4vp.conformance;

import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceModuleVariant;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceResult;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.CredentialProfile;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.keycloak.common.util.PemUtils;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

// Verifier accepts a valid presentation
@KeycloakIntegrationTest(config = AbstractVerifierConformanceTest.VerifierServerConfig.class)
class HappyFlowConformanceTest extends AbstractVerifierConformanceTest {

    @Override
    protected Stream<ConformanceModuleVariant> moduleVariants() {
        return verifierModuleVariants("oid4vp-1final-verifier-happy-flow", ConformanceResult.PASSED);
    }

    @Override
    protected void prepareModule(ConformanceModuleVariant moduleVariant) {
        assumeMdlIssuerCertificateNotExpired(moduleVariant);
        super.prepareModule(moduleVariant);
    }

    /**
     * The suite signs mdoc credentials with a hard-coded mDL issuer certificate that expired on
     * 2026-07-30 in every released suite version (conformance-suite issues #1628 and #1663 track
     * making that key material configurable). The verifier rightly rejects presentations from an
     * expired issuer certificate, so mdoc happy-flow modules cannot pass until the suite renews
     * the certificate. The expiry is read from the checked-in copy of that certificate, so the
     * skip lifts on its own once the renewed certificate and matching suite image are picked up.
     */
    private static void assumeMdlIssuerCertificateNotExpired(ConformanceModuleVariant moduleVariant) {
        if (!"iso_mdl".equals(moduleVariant.planVariant().get("credential_format"))) {
            return;
        }
        X509Certificate mdlIssuerCert = PemUtils.decodeCertificate(CredentialProfile.MDL_ISSUER_CERTIFICATE_PEM);
        Instant notAfter = mdlIssuerCert.getNotAfter().toInstant();
        Assumptions.assumeTrue(
                Instant.now().isBefore(notAfter),
                "The conformance suite's hard-coded mDL issuer certificate expired " + notAfter
                        + "; mdoc presentations cannot verify until the suite renews it");
    }
}
