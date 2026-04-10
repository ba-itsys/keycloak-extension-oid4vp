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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Provides Server-Sent Events (SSE) for cross-device OID4VP login polling.
 *
 * <p>Each SSE subscriber gets its own lightweight virtual thread that polls shared Keycloak state
 * until the flow completes, expires, times out, or the browser disconnects.
 */
public class Oid4vpCrossDeviceSseService {

    private static final Logger LOG = Logger.getLogger(Oid4vpCrossDeviceSseService.class);
    private static final String WORKER_NAME_PREFIX = "oid4vp-cross-device-sse-";
    private static final Set<Thread> ACTIVE_WORKERS = ConcurrentHashMap.newKeySet();

    private final String realmName;
    private final int timeoutSeconds;
    private final int pingIntervalSeconds;
    private final int pollIntervalMs;
    private final KeycloakSession requestSession;
    private final KeycloakSessionFactory sessionFactory;

    public Oid4vpCrossDeviceSseService(KeycloakSession session, RealmModel realm, Oid4vpConfigProvider config) {
        this.realmName = realm.getName();
        this.timeoutSeconds = config.getSseTimeoutSeconds();
        this.pingIntervalSeconds = config.getSsePingIntervalSeconds();
        this.pollIntervalMs = config.getSsePollIntervalMs();
        this.requestSession = session;
        this.sessionFactory = session.getKeycloakSessionFactory();
    }

    public void subscribe(String requestHandle, SseEventSink eventSink, Sse sse) {
        subscribe(requestHandle, eventSink, sse, null);
    }

    public void subscribe(
            String requestHandle, SseEventSink eventSink, Sse sse, AuthenticationSessionModel authSession) {
        PendingConnection connection = new PendingConnection(
                requestHandle,
                eventSink,
                sse,
                Instant.now().plusSeconds(timeoutSeconds),
                Instant.now().plusSeconds(pingIntervalSeconds),
                authSessionRootId(authSession),
                authSessionTabId(authSession),
                authSessionClientId(authSession));
        if (sessionFactory == null) {
            LOG.warn("Cross-device SSE disabled because no KeycloakSessionFactory is available");
            sendAndCloseError(connection, "error", "sse_unavailable");
            return;
        }
        PollResult immediateResult = pollCurrentRequest(connection);
        if (immediateResult != null && handlePollResult(connection, immediateResult)) {
            return;
        }

        Thread worker = Thread.ofVirtual()
                .name(WORKER_NAME_PREFIX + requestHandle, 0)
                .inheritInheritableThreadLocals(false)
                .unstarted(() -> run(connection));
        ACTIVE_WORKERS.add(worker);
        worker.start();
    }

    static void resetCoordinatorsForTests() {
        for (Thread worker : ACTIVE_WORKERS) {
            worker.interrupt();
        }
        ACTIVE_WORKERS.clear();
    }

    private void run(PendingConnection connection) {
        try {
            while (!connection.eventSink().isClosed()) {
                Instant now = Instant.now();
                if (!now.isBefore(connection.deadline())) {
                    sendAndCloseError(connection, "timeout", "timeout");
                    return;
                }

                PollResult pollResult = poll(connection);
                if (pollResult == null) {
                    closeQuietly(connection.eventSink());
                    return;
                }

                if (handlePollResult(connection, pollResult)) {
                    return;
                }
                if (!now.isBefore(connection.nextPingAt())) {
                    if (!send(connection, "ping", "{}")) {
                        return;
                    }
                    connection.setNextPingAt(now.plusSeconds(pingIntervalSeconds));
                }

                try {
                    // This stream is implemented as lightweight polling against shared Keycloak
                    // state. The sleep keeps idle connections cheap while still reacting quickly
                    // once the wallet callback stores the completion signal.
                    Thread.sleep(Math.max(10, pollIntervalMs));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    closeQuietly(connection.eventSink());
                    return;
                }
            }
        } catch (RuntimeException ex) {
            LOG.warnf(ex, "Cross-device SSE stream failed for %s", connection.requestHandle());
            closeQuietly(connection.eventSink());
        } finally {
            ACTIVE_WORKERS.remove(Thread.currentThread());
        }
    }

    private boolean handlePollResult(PendingConnection connection, PollResult pollResult) {
        switch (pollResult.status()) {
            case COMPLETE -> {
                sendAndClose(
                        connection,
                        "complete",
                        toJson(Map.of(OAuth2Constants.REDIRECT_URI, pollResult.completeAuthUrl())));
                return true;
            }
            case AUTHENTICATION_SESSION_EXPIRED -> {
                sendAndCloseError(connection, "expired", "authentication_session_expired");
                return true;
            }
            case REALM_NOT_FOUND -> {
                sendAndCloseError(connection, "error", "realm_not_found");
                return true;
            }
            case PENDING -> {
                return false;
            }
        }
        return false;
    }

    private PollResult pollCurrentRequest(PendingConnection connection) {
        if (requestSession == null) {
            return null;
        }
        try {
            RealmModel realm = requestSession.realms().getRealmByName(realmName);
            if (realm == null) {
                return PollResult.realmNotFound();
            }

            SingleUseObjectProvider store = requestSession.singleUseObjects();
            Map<String, String> signal = store.get(CROSS_DEVICE_COMPLETE_PREFIX + connection.requestHandle());
            String completeAuthUrl = signal != null ? signal.get(KEY_COMPLETE_AUTH_URL) : null;
            if (completeAuthUrl != null) {
                return PollResult.complete(completeAuthUrl);
            }

            if (isAuthenticationSessionExpired(requestSession, realm, connection)) {
                return PollResult.authenticationSessionExpired();
            }

            return PollResult.pending();
        } catch (RuntimeException ex) {
            LOG.debugf(ex, "Immediate cross-device SSE check failed for %s", connection.requestHandle());
            return null;
        }
    }

    private PollResult poll(PendingConnection connection) {
        try (KeycloakSession pollingSession = sessionFactory.create()) {
            pollingSession.getTransactionManager().begin();
            try {
                RealmModel realm = pollingSession.realms().getRealmByName(realmName);
                if (realm == null) {
                    pollingSession.getTransactionManager().commit();
                    return PollResult.realmNotFound();
                }

                SingleUseObjectProvider store = pollingSession.singleUseObjects();
                Map<String, String> signal = store.get(CROSS_DEVICE_COMPLETE_PREFIX + connection.requestHandle());
                String completeAuthUrl = signal != null ? signal.get(KEY_COMPLETE_AUTH_URL) : null;
                if (completeAuthUrl != null) {
                    pollingSession.getTransactionManager().commit();
                    return PollResult.complete(completeAuthUrl);
                }

                if (isAuthenticationSessionExpired(pollingSession, realm, connection)) {
                    pollingSession.getTransactionManager().commit();
                    return PollResult.authenticationSessionExpired();
                }

                pollingSession.getTransactionManager().commit();
                return PollResult.pending();
            } catch (RuntimeException ex) {
                rollbackQuietly(pollingSession);
                throw ex;
            }
        }
    }

    private boolean isAuthenticationSessionExpired(
            KeycloakSession pollingSession, RealmModel realm, PendingConnection connection) {
        if (StringUtil.isBlank(connection.rootSessionId()) || StringUtil.isBlank(connection.tabId())) {
            return false;
        }

        RootAuthenticationSessionModel rootSession =
                pollingSession.authenticationSessions().getRootAuthenticationSession(realm, connection.rootSessionId());
        if (rootSession == null) {
            return true;
        }

        AuthenticationSessionModel authSession =
                rootSession.getAuthenticationSessions().get(connection.tabId());
        if (authSession == null) {
            return true;
        }

        if (StringUtil.isBlank(connection.clientId())) {
            return false;
        }
        return authSession.getClient() == null
                || !connection.clientId().equals(authSession.getClient().getId());
    }

    private void rollbackQuietly(KeycloakSession session) {
        try {
            session.getTransactionManager().rollback();
        } catch (Exception rollbackError) {
            LOG.debugf(rollbackError, "Failed to roll back cross-device SSE poll transaction");
        }
    }

    private void sendAndClose(PendingConnection connection, String eventType, String data) {
        send(connection, eventType, data);
        closeQuietly(connection.eventSink());
    }

    private void sendAndCloseError(PendingConnection connection, String eventType, String errorCode) {
        sendAndClose(connection, eventType, toJson(Map.of("error", errorCode)));
    }

    private boolean send(PendingConnection connection, String eventType, String data) {
        try {
            OutboundSseEvent event = connection
                    .sse()
                    .newEventBuilder()
                    .name(eventType)
                    .mediaType(MediaType.APPLICATION_JSON_TYPE)
                    .data(String.class, data)
                    .build();
            connection.eventSink().send(event);
            return true;
        } catch (Exception ex) {
            LOG.debugf(ex, "Failed to send SSE event '%s' for %s", eventType, connection.requestHandle());
            closeQuietly(connection.eventSink());
            return false;
        }
    }

    private void closeQuietly(SseEventSink eventSink) {
        try {
            eventSink.close();
        } catch (Exception ignored) {
        }
    }

    private String toJson(Map<String, ?> payload) {
        try {
            return JsonSerialization.writeValueAsString(payload);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to serialize SSE payload", ex);
        }
    }

    private record PollResult(PollStatus status, String completeAuthUrl) {
        private static PollResult pending() {
            return new PollResult(PollStatus.PENDING, null);
        }

        private static PollResult complete(String completeAuthUrl) {
            return new PollResult(PollStatus.COMPLETE, completeAuthUrl);
        }

        private static PollResult realmNotFound() {
            return new PollResult(PollStatus.REALM_NOT_FOUND, null);
        }

        private static PollResult authenticationSessionExpired() {
            return new PollResult(PollStatus.AUTHENTICATION_SESSION_EXPIRED, null);
        }
    }

    private enum PollStatus {
        PENDING,
        COMPLETE,
        REALM_NOT_FOUND,
        AUTHENTICATION_SESSION_EXPIRED
    }

    private static final class PendingConnection {
        private final String requestHandle;
        private final SseEventSink eventSink;
        private final Sse sse;
        private final Instant deadline;
        private final String rootSessionId;
        private final String tabId;
        private final String clientId;
        private volatile Instant nextPingAt;

        private PendingConnection(
                String requestHandle,
                SseEventSink eventSink,
                Sse sse,
                Instant deadline,
                Instant nextPingAt,
                String rootSessionId,
                String tabId,
                String clientId) {
            this.requestHandle = requestHandle;
            this.eventSink = eventSink;
            this.sse = sse;
            this.deadline = deadline;
            this.nextPingAt = nextPingAt;
            this.rootSessionId = rootSessionId;
            this.tabId = tabId;
            this.clientId = clientId;
        }

        private String requestHandle() {
            return requestHandle;
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
