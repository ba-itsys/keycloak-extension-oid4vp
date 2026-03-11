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
package de.arbeitsagentur.keycloak.oid4vp.it.conformance;

import java.net.URI;
import java.util.Map;

record OidfConformanceSettings(
        URI suiteBaseUrl,
        String apiKey,
        String planName,
        String requestedModule,
        String publicBaseUrl,
        boolean keepPlansOnSuccess,
        boolean runInCi) {

    private static final String DEFAULT_SUITE_BASE_URL = "https://demo.certification.openid.net";
    private static final String DEFAULT_PLAN_NAME = "oid4vp-1final-verifier-test-plan";

    static OidfConformanceSettings load() {
        Map<String, String> dotEnv = DotEnvLoader.loadFromWorkingDirectory();
        return load(System.getenv(), dotEnv);
    }

    static OidfConformanceSettings load(Map<String, String> environment, Map<String, String> dotEnv) {
        return new OidfConformanceSettings(
                URI.create(firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_BASE_URL"),
                        environment.get("OIDF_CONFORMANCE_BASE_URL"),
                        dotEnv.get("OID4VP_CONFORMANCE_BASE_URL"),
                        dotEnv.get("OIDF_CONFORMANCE_BASE_URL"),
                        DEFAULT_SUITE_BASE_URL)),
                firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_API_KEY"),
                        environment.get("OIDF_CONFORMANCE_API_KEY"),
                        dotEnv.get("OID4VP_CONFORMANCE_API_KEY"),
                        dotEnv.get("OIDF_CONFORMANCE_API_KEY")),
                firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_PLAN_NAME"),
                        dotEnv.get("OID4VP_CONFORMANCE_PLAN_NAME"),
                        DEFAULT_PLAN_NAME),
                firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_TEST_MODULE"),
                        dotEnv.get("OID4VP_CONFORMANCE_TEST_MODULE")),
                firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_PUBLIC_BASE_URL"),
                        dotEnv.get("OID4VP_CONFORMANCE_PUBLIC_BASE_URL")),
                Boolean.parseBoolean(firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_KEEP_PLANS_ON_SUCCESS"),
                        dotEnv.get("OID4VP_CONFORMANCE_KEEP_PLANS_ON_SUCCESS"),
                        "true")),
                Boolean.parseBoolean(firstNonBlank(
                        environment.get("OID4VP_CONFORMANCE_RUN_IN_CI"),
                        dotEnv.get("OID4VP_CONFORMANCE_RUN_IN_CI"),
                        "false")));
    }

    boolean hasApiKey() {
        return apiKey != null && !apiKey.isBlank();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
