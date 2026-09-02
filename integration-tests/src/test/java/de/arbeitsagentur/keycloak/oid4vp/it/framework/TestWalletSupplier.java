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
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.keycloak.testframework.injection.InstanceContext;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.injection.RequestedInstance;
import org.keycloak.testframework.injection.Supplier;
import org.keycloak.testframework.injection.SupplierHelpers;
import org.keycloak.testframework.injection.SupplierOrder;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakServerConfigInterceptor;
import org.testcontainers.utility.DockerImageName;

/**
 * Supplies eudi-dev wallet containers. Every wallet is seeded with the same stable certificate
 * authority (see {@link WalletCertificateAuthority}), which this supplier also registers in the
 * Keycloak server's truststore, so the server can fetch issuer metadata and status lists over HTTPS
 * from any wallet, including ones started later in the run.
 */
public class TestWalletSupplier
        implements Supplier<TestWallet, InjectTestWallet>,
                KeycloakServerConfigInterceptor<TestWallet, InjectTestWallet> {

    @ConfigProperty(name = "image", defaultValue = "ghcr.io/dominikschlosser/eudi-dev:v2.3.2")
    String image;

    @ConfigProperty(name = "port", defaultValue = "18085")
    Integer port;

    @Override
    public TestWallet getValue(InstanceContext<TestWallet, InjectTestWallet> instanceContext) {
        TestWalletConfig config =
                SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
        TestWalletConfigBuilder builder = config.configure(new TestWalletConfigBuilder());

        EudiWalletContainer container = builder.build(
                DockerImageName.parse(image),
                WalletCertificateAuthority.instance().createSeededWalletStateDir(),
                port);
        container.start();
        try {
            return new TestWallet(container, "http://localhost:" + port);
        } catch (RuntimeException e) {
            // The wallet constructor talks to the container, and a failure here must not leak the
            // started container along with its fixed host ports.
            container.stop();
            throw e;
        }
    }

    @Override
    public KeycloakServerConfigBuilder intercept(
            KeycloakServerConfigBuilder serverConfig, InstanceContext<TestWallet, InjectTestWallet> instanceContext) {
        return serverConfig.option(
                "truststore-paths",
                WalletCertificateAuthority.instance().caCertPemPath().toString());
    }

    @Override
    public boolean compatible(
            InstanceContext<TestWallet, InjectTestWallet> a, RequestedInstance<TestWallet, InjectTestWallet> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public void close(InstanceContext<TestWallet, InjectTestWallet> instanceContext) {
        instanceContext.getValue().close();
    }

    @Override
    public int order() {
        return SupplierOrder.BEFORE_KEYCLOAK_SERVER;
    }
}
