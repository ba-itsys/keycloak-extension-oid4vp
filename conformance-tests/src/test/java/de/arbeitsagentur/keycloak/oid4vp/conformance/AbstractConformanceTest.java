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

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.conformance.containers.InjectConformanceSuite;
import de.arbeitsagentur.keycloak.oid4vp.conformance.containers.OpenIdConformanceSuite;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceModuleResult;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceModuleVariant;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ModuleRun;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.testframework.https.CertificatesConfig;
import org.keycloak.testframework.https.CertificatesConfigBuilder;
import org.keycloak.testframework.https.InjectCertificates;
import org.keycloak.testframework.https.ManagedCertificates;

/**
 * Base class for all conformance areas. Test classes target one conformance module via
 * {@link #moduleVariants()} and assert it finishes with the result expected for that module
 * across every applicable variant combination.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractConformanceTest {

    private static final Logger LOGGER = Logger.getLogger(AbstractConformanceTest.class);

    // Not used directly, but required to start the Keycloak server with TLS enabled
    @InjectCertificates(config = TlsCertificates.class)
    ManagedCertificates certificates;

    @InjectConformanceSuite
    protected OpenIdConformanceSuite suite;

    protected abstract Stream<ConformanceModuleVariant> moduleVariants();

    protected abstract JsonNode suiteConfig(ConformanceModuleVariant moduleVariant);

    // Prepares the system under test for the given variant before the module runs
    protected void prepareModule(ConformanceModuleVariant moduleVariant) {}

    // Drives the system under test once the module waits for it
    protected void interact(ConformanceModuleVariant moduleVariant, ModuleRun moduleRun) {}

    @ParameterizedTest
    @MethodSource("moduleVariants")
    void conformance(ConformanceModuleVariant moduleVariant) {
        prepareModule(moduleVariant);
        ConformanceModuleResult result = suite.client()
                .run(moduleVariant, suiteConfig(moduleVariant), moduleRun -> interact(moduleVariant, moduleRun));
        boolean passed = result.finishedWith(moduleVariant.expectedResult());
        if (!passed) {
            LOGGER.errorf(
                    "Full logs of failed conformance module %s:%n%s",
                    result.module(), result.logs().toPrettyString());
            Assertions.fail(result.failureSummary());
        }
    }

    public static class TlsCertificates implements CertificatesConfig {

        @Override
        public CertificatesConfigBuilder configure(CertificatesConfigBuilder config) {
            return config.tlsEnabled(true);
        }
    }
}
