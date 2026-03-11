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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class OidfConformanceSettingsTest {

    @Test
    void keepsPlansByDefaultWhenSettingIsNotProvided() {
        OidfConformanceSettings settings =
                OidfConformanceSettings.load(Map.of(), Map.of("OIDF_CONFORMANCE_API_KEY", "test-token"));

        assertThat(settings.keepPlansOnSuccess()).isTrue();
    }

    @Test
    void allowsExplicitOptOutOfKeepingPlans() {
        OidfConformanceSettings settings =
                OidfConformanceSettings.load(Map.of(), Map.of("OID4VP_CONFORMANCE_KEEP_PLANS_ON_SUCCESS", "false"));

        assertThat(settings.keepPlansOnSuccess()).isFalse();
    }
}
