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

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Builder for the wallet container backing a {@link TestWallet}.
 *
 * <p>The wallet advertises {@code localhost} URLs on a fixed port (HTTPS on port + 1), so only
 * one wallet runs at a time. When a test class requests a wallet with a different configuration,
 * the test framework replaces the running wallet automatically.
 */
public final class TestWalletConfigBuilder {

    private static final String WALLET_STATE_CONTAINER_DIR = "/home/app/.oid4vc-dev";

    private boolean statusList = true;
    private boolean requireEncryptedRequest;
    private String sessionTranscript;
    private final List<UnaryOperator<Oid4vcContainer>> customizers = new ArrayList<>();

    // Whether the wallet embeds status list references in generated credentials (default on)
    public TestWalletConfigBuilder statusList(boolean statusList) {
        this.statusList = statusList;
        return this;
    }

    // Requires verifiers to encrypt OID4VP request objects
    public TestWalletConfigBuilder requireEncryptedRequest() {
        this.requireEncryptedRequest = true;
        return this;
    }

    // The mDoc session transcript mode: oid4vp (default) or iso
    public TestWalletConfigBuilder sessionTranscript(String mode) {
        this.sessionTranscript = mode;
        return this;
    }

    // Escape hatch for container settings not covered by this builder
    public TestWalletConfigBuilder customize(UnaryOperator<Oid4vcContainer> customizer) {
        customizers.add(customizer);
        return this;
    }

    Oid4vcContainer build(DockerImageName image, Path walletStateDir, int port) {
        int tlsPort = port + 1;
        Oid4vcContainer container = new TestWalletContainer(image, port)
                .withHostAccess()
                .withBaseUrl("http://localhost:" + port)
                .withFileSystemBind(walletStateDir.toString(), WALLET_STATE_CONTAINER_DIR, BindMode.READ_WRITE)
                .withExposedPorts(port, tlsPort)
                .withCreateContainerCmdModifier(cmd -> {
                    cmd.getHostConfig()
                            .withPortBindings(
                                    new PortBinding(Ports.Binding.bindPort(port), ExposedPort.tcp(port)),
                                    new PortBinding(Ports.Binding.bindPort(tlsPort), ExposedPort.tcp(tlsPort)));
                    // Relocate the wallet's HTTP port (HTTPS is always served on the next port)
                    // away from the default so the tests do not collide with a locally running wallet
                    String[] command = cmd.getCmd();
                    if (command != null) {
                        for (int i = 0; i < command.length - 1; i++) {
                            if ("--port".equals(command[i])) {
                                command[i + 1] = String.valueOf(port);
                            }
                        }
                        cmd.withCmd(command);
                    }
                });
        container.waitingFor(Wait.forHttp("/").forPort(port));
        if (statusList) {
            container = container.withStatusList();
        }
        if (requireEncryptedRequest) {
            container = container.withRequireEncryptedRequest();
        }
        if (sessionTranscript != null) {
            container = container.withSessionTranscript(sessionTranscript);
        }
        for (UnaryOperator<Oid4vcContainer> customizer : customizers) {
            container = customizer.apply(container);
        }
        return container;
    }
}
