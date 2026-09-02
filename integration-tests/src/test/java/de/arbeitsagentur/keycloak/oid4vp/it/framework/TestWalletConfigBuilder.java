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
import io.github.dominikschlosser.eudi.EudiWalletContainer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

public final class TestWalletConfigBuilder {

    private static final String WALLET_STATE_CONTAINER_DIR = "/home/app/.eudi-dev";

    /**
     * Entrypoint wrapper that makes {@code localhost} resolve to the Docker host gateway inside the
     * wallet container before the wallet starts.
     *
     * <p>{@link EudiWalletContainer#withHostAccess()} adds a {@code <gateway> localhost} entry via
     * {@code --add-host}, but Docker writes the built-in {@code 127.0.0.1 localhost} and
     * {@code ::1 localhost} lines first, and the wallet's Go HTTP client takes the first match and
     * dials its own loopback. The wrapper therefore runs as root to strip the loopback
     * {@code localhost} lines, leaving only the gateway entry, then drops back to the unprivileged
     * {@code app} user and execs the original wallet command. Passing that command through as
     * {@code "$*"} is safe because every serve flag value is a single token.
     *
     * <p>Without this the wallet cannot fetch the {@code request_uri} or POST to the
     * {@code response_uri} of Keycloak running on the host. That fails on Linux CI, while on Docker
     * Desktop it happens to work through gateway fallthrough.
     */
    private static final String LOCALHOST_TO_HOST_GATEWAY_ENTRYPOINT =
            "grep -vE '^(127\\.0\\.0\\.1|::1)[[:space:]]+localhost([[:space:]]|$)' /etc/hosts > /tmp/hosts "
                    + "&& cat /tmp/hosts > /etc/hosts; "
                    + "exec su app -s /bin/sh -c \"HOME=/home/app exec eudi $*\"";

    private boolean statusList = true;
    private boolean requireEncryptedRequest;
    private String sessionTranscript;
    private final List<UnaryOperator<EudiWalletContainer>> customizers = new ArrayList<>();

    public TestWalletConfigBuilder statusList(boolean statusList) {
        this.statusList = statusList;
        return this;
    }

    public TestWalletConfigBuilder requireEncryptedRequest() {
        this.requireEncryptedRequest = true;
        return this;
    }

    // Sets the mdoc session transcript mode, either oid4vp (the default) or iso.
    public TestWalletConfigBuilder sessionTranscript(String mode) {
        this.sessionTranscript = mode;
        return this;
    }

    public TestWalletConfigBuilder customize(UnaryOperator<EudiWalletContainer> customizer) {
        customizers.add(customizer);
        return this;
    }

    EudiWalletContainer build(DockerImageName image, Path walletStateDir, int port) {
        int tlsPort = port + 1;
        EudiWalletContainer container = new TestWalletContainer(image, port)
                .withHostAccess()
                .withBaseUrl("http://localhost:" + port)
                .withFileSystemBind(walletStateDir.toString(), WALLET_STATE_CONTAINER_DIR, BindMode.READ_WRITE)
                .withExposedPorts(port, tlsPort)
                .withCreateContainerCmdModifier(cmd -> {
                    cmd.getHostConfig()
                            .withPortBindings(
                                    new PortBinding(Ports.Binding.bindPort(port), ExposedPort.tcp(port)),
                                    new PortBinding(Ports.Binding.bindPort(tlsPort), ExposedPort.tcp(tlsPort)));
                    String[] command = cmd.getCmd();
                    if (command != null) {
                        for (int i = 0; i < command.length - 1; i++) {
                            if ("--port".equals(command[i])) {
                                command[i + 1] = String.valueOf(port);
                            }
                        }
                        cmd.withCmd(command);
                    }
                    // Runs as root so the entrypoint can rewrite /etc/hosts, which is a Docker bind
                    // mount and can only be edited in place. The wrapper drops back to the 'app' user
                    // afterwards.
                    cmd.withUser("0");
                    cmd.withEntrypoint("/bin/sh", "-c", LOCALHOST_TO_HOST_GATEWAY_ENTRYPOINT, "sh");
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
        for (UnaryOperator<EudiWalletContainer> customizer : customizers) {
            container = customizer.apply(container);
        }
        return container;
    }
}
