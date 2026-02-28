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

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpDirectPostService.CROSS_DEVICE_COMPLETE_PREFIX;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.util.JsonSerialization;

class Oid4vpCrossDeviceSseService {

    private static final Logger LOG = Logger.getLogger(Oid4vpCrossDeviceSseService.class);

    private final KeycloakSessionFactory sessionFactory;
    private final String realmName;
    private final int pollIntervalMs;
    private final int maxIterations;
    private final int pingEveryIterations;

    Oid4vpCrossDeviceSseService(KeycloakSession session, RealmModel realm, Oid4vpIdentityProviderConfig config) {
        this.sessionFactory = session.getKeycloakSessionFactory();
        this.realmName = realm.getName();
        this.pollIntervalMs = config.getSsePollIntervalMs();

        int timeoutSeconds = config.getSseTimeoutSeconds();
        this.maxIterations = Math.max(1, (timeoutSeconds * 1000) / pollIntervalMs);

        int pingIntervalSeconds = config.getSsePingIntervalSeconds();
        this.pingEveryIterations = Math.max(1, (pingIntervalSeconds * 1000) / pollIntervalMs);
    }

    Response buildSseResponse(String state) {
        StreamingOutput stream = output -> {
            try {
                for (int i = 0; i < maxIterations; i++) {
                    try (KeycloakSession pollingSession = sessionFactory.create()) {
                        pollingSession.getTransactionManager().begin();
                        try {
                            RealmModel pollingRealm = pollingSession.realms().getRealmByName(realmName);
                            if (pollingRealm == null) {
                                writeSseEvent(output, "error", "{\"error\":\"realm_not_found\"}");
                                return;
                            }
                            SingleUseObjectProvider store = pollingSession.singleUseObjects();
                            Map<String, String> entry = store.remove(CROSS_DEVICE_COMPLETE_PREFIX + state);
                            if (entry != null) {
                                String completeAuthUrl = entry.get("complete_auth_url");
                                if (completeAuthUrl != null) {
                                    writeSseEvent(
                                            output,
                                            "complete",
                                            JsonSerialization.writeValueAsString(
                                                    Map.of("redirect_uri", completeAuthUrl)));
                                    pollingSession.getTransactionManager().commit();
                                    return;
                                }
                            }
                            pollingSession.getTransactionManager().commit();
                        } catch (Exception e) {
                            pollingSession.getTransactionManager().rollback();
                        }
                    }

                    if (i % pingEveryIterations == 0) {
                        writeSseEvent(output, "ping", "{}");
                    }

                    Thread.sleep(pollIntervalMs);
                }

                writeSseEvent(output, "timeout", "{\"error\":\"timeout\"}");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // Client disconnected
            }
        };

        return Response.ok(stream)
                .type("text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .header("X-Accel-Buffering", "no")
                .build();
    }

    private void writeSseEvent(OutputStream output, String eventType, String data) throws IOException {
        output.write(("event: " + eventType + "\n").getBytes(StandardCharsets.UTF_8));
        output.write(("data: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
        output.flush();
    }
}
