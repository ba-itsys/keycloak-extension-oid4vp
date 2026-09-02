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
package de.arbeitsagentur.keycloak.oid4vp.it.framework;

import io.github.dominikschlosser.eudi.EudiWalletContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * {@link EudiWalletContainer} that serves the wallet on a custom port instead of the default, with
 * HTTPS on the next port, so that a test run does not collide with a locally running eudi-dev.
 */
final class TestWalletContainer extends EudiWalletContainer {

    private final int port;

    TestWalletContainer(DockerImageName image, int port) {
        super(image);
        this.port = port;
    }

    @Override
    public String getBaseUrl() {
        return "http://" + getHost() + ":" + getMappedPort(port);
    }

    @Override
    public String getHttpsBaseUrl() {
        return "https://" + getHost() + ":" + getMappedPort(port + 1);
    }
}
