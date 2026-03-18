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
package de.arbeitsagentur.keycloak.oid4vp.service;

import static de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService.CROSS_DEVICE_COMPLETE_PREFIX;
import static de.arbeitsagentur.keycloak.oid4vp.service.Oid4vpDirectPostService.KEY_COMPLETE_AUTH_URL;

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConfigProvider;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.sse.OutboundSseEvent;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.timer.TimerProvider;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Provides Server-Sent Events (SSE) for cross-device OID4VP login polling.
 *
 * <p>In the cross-device flow, the user scans a QR code with their wallet on a separate device.
 * The browser holds an SSE connection to this service, which polls Keycloak's
 * {@link org.keycloak.models.SingleUseObjectProvider} for a completion signal. When the wallet's
 * direct_post response has been processed, the SSE stream emits a {@code complete} event with
 * a redirect URL so the browser can finalize authentication.
 */
public class Oid4vpCrossDeviceSseService {

    private static final Logger LOG = Logger.getLogger(Oid4vpCrossDeviceSseService.class);
    private static final ConcurrentHashMap<KeycloakSessionFactory, PollCoordinator> COORDINATORS =
            new ConcurrentHashMap<>();

    private final String realmName;
    private final int timeoutSeconds;
    private final int pingIntervalSeconds;
    private final int pollIntervalMs;
    private final PollCoordinator coordinator;

    public Oid4vpCrossDeviceSseService(KeycloakSession session, RealmModel realm, Oid4vpConfigProvider config) {
        this.realmName = realm.getName();
        this.timeoutSeconds = config.getSseTimeoutSeconds();
        this.pingIntervalSeconds = config.getSsePingIntervalSeconds();
        this.pollIntervalMs = config.getSsePollIntervalMs();
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        if (sessionFactory == null) {
            LOG.warn("Cross-device SSE disabled because no KeycloakSessionFactory is available");
            this.coordinator = PollCoordinator.unavailable();
        } else {
            this.coordinator = COORDINATORS.computeIfAbsent(sessionFactory, PollCoordinator::new);
        }
    }

    public void subscribe(String requestHandle, SseEventSink eventSink, Sse sse) {
        subscribe(requestHandle, eventSink, sse, true);
    }

    public void subscribe(
            String requestHandle, SseEventSink eventSink, Sse sse, AuthenticationSessionModel authSession) {
        coordinator.register(
                new PendingConnection(
                        new HandleKey(realmName, requestHandle),
                        eventSink,
                        sse,
                        Instant.now().plusSeconds(timeoutSeconds),
                        pingIntervalSeconds,
                        pollIntervalMs,
                        Instant.now().plusSeconds(pingIntervalSeconds),
                        authSessionRootId(authSession),
                        authSessionTabId(authSession),
                        authSessionClientId(authSession)),
                true);
    }

    void subscribe(String requestHandle, SseEventSink eventSink, Sse sse, boolean startScheduler) {
        coordinator.register(
                new PendingConnection(
                        new HandleKey(realmName, requestHandle),
                        eventSink,
                        sse,
                        Instant.now().plusSeconds(timeoutSeconds),
                        pingIntervalSeconds,
                        pollIntervalMs,
                        Instant.now().plusSeconds(pingIntervalSeconds),
                        null,
                        null,
                        null),
                startScheduler);
    }

    void pollOnce() {
        coordinator.pollOnce();
    }

    static void resetCoordinatorsForTests() {
        for (PollCoordinator coordinator : COORDINATORS.values()) {
            coordinator.shutdown();
        }
        COORDINATORS.clear();
    }

    private static final class PollCoordinator {

        private static final PollCoordinator UNAVAILABLE = new PollCoordinator(null);
        private static final String TASK_NAME = "oid4vp-cross-device-sse";

        private final KeycloakSessionFactory sessionFactory;
        private final ConcurrentHashMap<HandleKey, CopyOnWriteArrayList<PendingConnection>> pendingConnections =
                new ConcurrentHashMap<>();
        private final AtomicBoolean started = new AtomicBoolean(false);
        private final AtomicBoolean shutdown = new AtomicBoolean(false);
        private final AtomicInteger scheduledIntervalMs = new AtomicInteger(Integer.MAX_VALUE);

        private PollCoordinator(KeycloakSessionFactory sessionFactory) {
            this.sessionFactory = sessionFactory;
        }

        private static PollCoordinator unavailable() {
            return UNAVAILABLE;
        }

        private void register(PendingConnection connection, boolean startScheduler) {
            if (sessionFactory == null) {
                sendAndClose(connection, "error", "{\"error\":\"sse_unavailable\"}");
                return;
            }
            pendingConnections
                    .computeIfAbsent(connection.handleKey(), key -> new CopyOnWriteArrayList<>())
                    .add(connection);
            if (startScheduler) {
                reconcileSchedule();
            }
        }

        private synchronized void reconcileSchedule() {
            if (shutdown.get() || sessionFactory == null) {
                return;
            }

            int desiredIntervalMs = desiredPollIntervalMs();
            if (desiredIntervalMs == Integer.MAX_VALUE) {
                cancelScheduledTask();
                started.set(false);
                return;
            }

            if (started.compareAndSet(false, true)) {
                schedule(desiredIntervalMs);
                return;
            }

            if (desiredIntervalMs != scheduledIntervalMs.get()) {
                reschedule(desiredIntervalMs);
            }
        }

        private int desiredPollIntervalMs() {
            int desired = Integer.MAX_VALUE;
            for (CopyOnWriteArrayList<PendingConnection> listeners : pendingConnections.values()) {
                for (PendingConnection listener : listeners) {
                    desired = Math.min(desired, listener.pollIntervalMs());
                }
            }
            return desired;
        }

        private synchronized void reschedule(int intervalMs) {
            if (shutdown.get() || sessionFactory == null) {
                return;
            }
            cancelScheduledTask();
            schedule(intervalMs);
        }

        private void schedule(int intervalMs) {
            try (KeycloakSession schedulerSession = sessionFactory.create()) {
                TimerProvider timer = schedulerSession.getProvider(TimerProvider.class);
                if (timer == null) {
                    throw new IllegalStateException("No TimerProvider available");
                }
                int effectiveIntervalMs = Math.max(50, intervalMs);
                timer.schedule(this::runScheduledPoll, effectiveIntervalMs, TASK_NAME);
                scheduledIntervalMs.set(effectiveIntervalMs);
            }
        }

        private void runScheduledPoll() {
            if (shutdown.get()) {
                return;
            }
            try {
                pollOnce();
            } catch (Exception e) {
                LOG.warnf(e, "Cross-device SSE poll loop failed: %s", e.getMessage());
            }
        }

        private void cancelScheduledTask() {
            if (sessionFactory == null) {
                return;
            }
            try (KeycloakSession schedulerSession = sessionFactory.create()) {
                TimerProvider timer = schedulerSession.getProvider(TimerProvider.class);
                if (timer == null) {
                    return;
                }
                timer.cancelTask(TASK_NAME);
            } catch (Exception e) {
                LOG.debugf("Failed to cancel cross-device SSE timer task: %s", e.getMessage());
            }
            scheduledIntervalMs.set(Integer.MAX_VALUE);
        }

        private void pollOnce() {
            if (pendingConnections.isEmpty()) {
                return;
            }

            Instant now = Instant.now();
            try (KeycloakSession pollingSession = sessionFactory.create()) {
                pollingSession.getTransactionManager().begin();
                try {
                    SingleUseObjectProvider store = pollingSession.singleUseObjects();
                    Map<String, RealmModel> realmsByName = new ConcurrentHashMap<>();
                    for (Map.Entry<HandleKey, CopyOnWriteArrayList<PendingConnection>> entry :
                            pendingConnections.entrySet()) {
                        HandleKey handleKey = entry.getKey();
                        CopyOnWriteArrayList<PendingConnection> listeners = entry.getValue();
                        if (listeners == null || listeners.isEmpty()) {
                            pendingConnections.remove(handleKey, listeners);
                            continue;
                        }

                        RealmModel realm = realmsByName.computeIfAbsent(
                                handleKey.realmName(), pollingSession.realms()::getRealmByName);
                        if (realm == null) {
                            closeAll(handleKey, listeners, "error", "{\"error\":\"realm_not_found\"}");
                            continue;
                        }

                        Map<String, String> signal =
                                store.get(CROSS_DEVICE_COMPLETE_PREFIX + handleKey.requestHandle());
                        String completeAuthUrl = signal != null ? signal.get(KEY_COMPLETE_AUTH_URL) : null;
                        if (completeAuthUrl != null) {
                            String payload = toJson(Map.of(OAuth2Constants.REDIRECT_URI, completeAuthUrl));
                            closeAll(handleKey, listeners, "complete", payload);
                            continue;
                        }

                        if (isAuthenticationSessionExpired(pollingSession, realm, listeners)) {
                            closeAll(handleKey, listeners, "expired", "{\"error\":\"authentication_session_expired\"}");
                            continue;
                        }

                        List<PendingConnection> expired = new ArrayList<>();
                        for (PendingConnection listener : listeners) {
                            if (listener.eventSink().isClosed()) {
                                expired.add(listener);
                                continue;
                            }
                            if (!now.isBefore(listener.deadline())) {
                                sendAndClose(listener, "timeout", "{\"error\":\"timeout\"}");
                                expired.add(listener);
                                continue;
                            }
                            if (!now.isBefore(listener.nextPingAt())) {
                                if (send(listener, "ping", "{}")) {
                                    listener.setNextPingAt(now.plusSeconds(listener.pingIntervalSeconds()));
                                } else {
                                    expired.add(listener);
                                }
                            }
                        }
                        listeners.removeAll(expired);
                        if (listeners.isEmpty()) {
                            pendingConnections.remove(handleKey, listeners);
                        }
                    }
                    pollingSession.getTransactionManager().commit();
                } catch (Exception e) {
                    pollingSession.getTransactionManager().rollback();
                    throw e;
                }
            }
            if (started.get()) {
                reconcileSchedule();
            }
        }

        private void closeAll(
                HandleKey handleKey, CopyOnWriteArrayList<PendingConnection> listeners, String eventType, String data) {
            for (PendingConnection listener : listeners) {
                sendAndClose(listener, eventType, data);
            }
            pendingConnections.remove(handleKey, listeners);
        }

        private void sendAndClose(PendingConnection listener, String eventType, String data) {
            send(listener, eventType, data);
            try {
                listener.eventSink().close();
            } catch (Exception ignored) {
            }
        }

        private boolean send(PendingConnection listener, String eventType, String data) {
            try {
                OutboundSseEvent event = listener.sse()
                        .newEventBuilder()
                        .name(eventType)
                        .mediaType(MediaType.APPLICATION_JSON_TYPE)
                        .data(String.class, data)
                        .build();
                listener.eventSink().send(event);
                return true;
            } catch (Exception e) {
                LOG.debugf("Failed to send SSE event '%s': %s", eventType, e.getMessage());
                try {
                    listener.eventSink().close();
                } catch (Exception ignored) {
                }
                return false;
            }
        }

        private void shutdown() {
            shutdown.set(true);
            cancelScheduledTask();
            for (CopyOnWriteArrayList<PendingConnection> listeners : pendingConnections.values()) {
                for (PendingConnection listener : listeners) {
                    try {
                        listener.eventSink().close();
                    } catch (Exception ignored) {
                    }
                }
            }
            pendingConnections.clear();
        }

        private String toJson(Map<String, String> payload) {
            try {
                return JsonSerialization.writeValueAsString(payload);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to serialize SSE payload", e);
            }
        }

        private boolean isAuthenticationSessionExpired(
                KeycloakSession pollingSession, RealmModel realm, CopyOnWriteArrayList<PendingConnection> listeners) {
            PendingConnection reference = null;
            for (PendingConnection listener : listeners) {
                if (StringUtil.isNotBlank(listener.rootSessionId()) && StringUtil.isNotBlank(listener.tabId())) {
                    reference = listener;
                    break;
                }
            }
            if (reference == null) {
                return false;
            }

            RootAuthenticationSessionModel rootSession = pollingSession
                    .authenticationSessions()
                    .getRootAuthenticationSession(realm, reference.rootSessionId());
            if (rootSession == null) {
                return true;
            }

            AuthenticationSessionModel authSession =
                    rootSession.getAuthenticationSessions().get(reference.tabId());
            if (authSession == null) {
                return true;
            }

            if (StringUtil.isBlank(reference.clientId())) {
                return false;
            }
            return authSession.getClient() == null
                    || !reference.clientId().equals(authSession.getClient().getId());
        }
    }

    private record HandleKey(String realmName, String requestHandle) {}

    private static final class PendingConnection {
        private final HandleKey handleKey;
        private final SseEventSink eventSink;
        private final Sse sse;
        private final Instant deadline;
        private final int pingIntervalSeconds;
        private final int pollIntervalMs;
        private final String rootSessionId;
        private final String tabId;
        private final String clientId;
        private volatile Instant nextPingAt;

        private PendingConnection(
                HandleKey handleKey,
                SseEventSink eventSink,
                Sse sse,
                Instant deadline,
                int pingIntervalSeconds,
                int pollIntervalMs,
                Instant nextPingAt,
                String rootSessionId,
                String tabId,
                String clientId) {
            this.handleKey = handleKey;
            this.eventSink = eventSink;
            this.sse = sse;
            this.deadline = deadline;
            this.nextPingAt = nextPingAt;
            this.pingIntervalSeconds = pingIntervalSeconds;
            this.pollIntervalMs = pollIntervalMs;
            this.rootSessionId = rootSessionId;
            this.tabId = tabId;
            this.clientId = clientId;
        }

        private HandleKey handleKey() {
            return handleKey;
        }

        private SseEventSink eventSink() {
            return eventSink;
        }

        private Sse sse() {
            return sse;
        }

        private Instant deadline() {
            return deadline;
        }

        private Instant nextPingAt() {
            return nextPingAt;
        }

        private int pingIntervalSeconds() {
            return pingIntervalSeconds;
        }

        private int pollIntervalMs() {
            return pollIntervalMs;
        }

        private String rootSessionId() {
            return rootSessionId;
        }

        private String tabId() {
            return tabId;
        }

        private String clientId() {
            return clientId;
        }

        private void setNextPingAt(Instant nextPingAt) {
            this.nextPingAt = nextPingAt;
        }
    }

    private static String authSessionRootId(AuthenticationSessionModel authSession) {
        return authSession != null && authSession.getParentSession() != null
                ? authSession.getParentSession().getId()
                : null;
    }

    private static String authSessionTabId(AuthenticationSessionModel authSession) {
        return authSession != null ? authSession.getTabId() : null;
    }

    private static String authSessionClientId(AuthenticationSessionModel authSession) {
        return authSession != null && authSession.getClient() != null
                ? authSession.getClient().getId()
                : null;
    }
}
