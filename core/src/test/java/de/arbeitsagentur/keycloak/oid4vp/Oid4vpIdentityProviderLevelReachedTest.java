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
package de.arbeitsagentur.keycloak.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperUtils;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;

class Oid4vpIdentityProviderLevelReachedTest {

    private final Oid4vpIdentityProviderConfig config = new Oid4vpIdentityProviderConfig();

    Oid4vpIdentityProviderLevelReachedTest() {
        config.setAlias("oid4vp");
        config.setEnabled(true);
        config.setSameDeviceLoa(4);
        config.setCrossDeviceLoa(3);
    }

    @Test
    void aLoginReachesTheLevelOfTheFlowItsPresentationArrivedOver() {
        assertThat(Oid4vpIdentityProvider.levelReached(config, login(Oid4vpConstants.FLOW_SAME_DEVICE)))
                .isEqualTo(4);
        assertThat(Oid4vpIdentityProvider.levelReached(config, login(Oid4vpConstants.FLOW_CROSS_DEVICE)))
                .isEqualTo(3);
    }

    @Test
    void aFlowWithoutLevelRecordsNone() {
        config.setCrossDeviceLoa(null);

        assertThat(Oid4vpIdentityProvider.levelReached(config, login(Oid4vpConstants.FLOW_CROSS_DEVICE)))
                .isNull();
    }

    @Test
    void aPresentationWithoutTheSubjectCredentialReachesNoLevel() {
        BrokeredIdentityContext login = login(Oid4vpConstants.FLOW_SAME_DEVICE);
        login.getContextData().put(Oid4vpMapperUtils.CONTEXT_GENERATED_SUBJECT_KEY, "generated");

        assertThat(Oid4vpIdentityProvider.levelReached(config, login)).isNull();
    }

    @Test
    void aLoginWithoutPresentationFlowReachesNoLevel() {
        assertThat(Oid4vpIdentityProvider.levelReached(config, login(null))).isNull();
    }

    private BrokeredIdentityContext login(String flow) {
        BrokeredIdentityContext context = new BrokeredIdentityContext("subject", config);
        if (flow != null) {
            context.getContextData().put(Oid4vpMapperUtils.CONTEXT_PRESENTATION_FLOW_KEY, flow);
        }
        return context;
    }
}
