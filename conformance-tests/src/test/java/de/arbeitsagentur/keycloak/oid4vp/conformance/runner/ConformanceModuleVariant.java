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
package de.arbeitsagentur.keycloak.oid4vp.conformance.runner;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpRejectionResponse;
import java.util.Map;

/**
 * A conformance suite test module to run in one variant combination. The plan variant is chosen when
 * the plan is created and applies plan wide, while the module variant picks which combination of the
 * module to run, since a plan can contain the same module several times.
 */
public record ConformanceModuleVariant(
        String plan,
        Map<String, String> planVariant,
        String name,
        Map<String, String> moduleVariant,
        ConformanceResult expectedResult,
        boolean allowSkipped,
        Oid4vpRejectionResponse rejectionResponse) {

    public ConformanceModuleVariant(
            String plan, Map<String, String> planVariant, String name, Map<String, String> moduleVariant) {
        this(plan, planVariant, name, moduleVariant, ConformanceResult.PASSED);
    }

    public ConformanceModuleVariant(
            String plan,
            Map<String, String> planVariant,
            String name,
            Map<String, String> moduleVariant,
            ConformanceResult expectedResult) {
        this(plan, planVariant, name, moduleVariant, expectedResult, false, Oid4vpRejectionResponse.REDIRECT);
    }

    public ConformanceModuleVariant withRejectionResponse(Oid4vpRejectionResponse rejectionResponse) {
        return new ConformanceModuleVariant(
                plan, planVariant, name, moduleVariant, expectedResult, allowSkipped, rejectionResponse);
    }

    /**
     * Returns a copy of this variant that also accepts a SKIPPED result from the suite. Only a module
     * covering a feature the verifier does not advertise opts in; every other module fails on an
     * unexpected skip.
     */
    public ConformanceModuleVariant allowingSkipped() {
        return new ConformanceModuleVariant(
                plan, planVariant, name, moduleVariant, expectedResult, true, rejectionResponse);
    }

    // Serves as the display name of a parameterized test run.
    @Override
    public String toString() {
        return name + " " + planVariant + " rejection=" + rejectionResponse.configValue();
    }
}
