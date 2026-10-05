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
package de.arbeitsagentur.keycloak.oid4vp.util;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.keycloak.broker.provider.util.SimpleHttp;

/**
 * Renders the details of a failure caused by something outside this verifier for log lines and error messages.
 * */
public final class FailureDetails {

    private static final int MAX_BODY_CHARS = 300;
    private static final int MAX_CAUSE_DEPTH = 10;
    private static final Pattern LINE_BREAKING_CHARACTERS = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    private FailureDetails() {}

    public static String causeChain(Throwable throwable) {
        StringBuilder text = new StringBuilder();
        int depth = 0;
        for (Throwable current = throwable; current != null && depth < MAX_CAUSE_DEPTH; current = current.getCause()) {
            depth++;
            String message = current.getMessage() != null
                    ? singleLine(current.getMessage())
                    : current.getClass().getSimpleName();
            if (text.indexOf(message) >= 0) {
                continue;
            }
            if (!text.isEmpty()) {
                text.append(" <- ");
            }
            text.append(message);
        }
        return text.toString();
    }

    public static String singleLine(String value) {
        return value != null ? LINE_BREAKING_CHARACTERS.matcher(value).replaceAll(" ") : null;
    }

    public static String bodySnippet(String body) {
        if (body == null || body.isBlank()) {
            return "<empty>";
        }
        String singleLine = singleLine(body.strip()).replaceAll(" +", " ");
        return singleLine.length() > MAX_BODY_CHARS
                ? singleLine.substring(0, MAX_BODY_CHARS) + "... (" + singleLine.length() + " chars)"
                : singleLine;
    }

    public static String httpResponse(SimpleHttp.Response response) {
        String contentType;
        try {
            contentType = response.getFirstHeader("Content-Type");
        } catch (Exception e) {
            contentType = "<unreadable>";
        }
        String body;
        try {
            body = bodySnippet(response.asString());
        } catch (Exception e) {
            body = "<unreadable: " + causeChain(e) + ">";
        }
        return "Content-Type: " + contentType + ", body: " + body;
    }

    public static String certificate(X509Certificate certificate) {
        if (certificate == null) {
            return "<none>";
        }
        return "[subject=" + singleLine(certificate.getSubjectX500Principal().getName())
                + ", issuer=" + singleLine(certificate.getIssuerX500Principal().getName())
                + ", serial=" + certificate.getSerialNumber().toString(16)
                + ", valid " + certificate.getNotBefore().toInstant()
                + " to " + certificate.getNotAfter().toInstant() + "]";
    }

    public static String certificates(Collection<X509Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return "[]";
        }
        return certificates.stream().map(FailureDetails::certificate).collect(Collectors.joining(", ", "[", "]"));
    }

    public static String relativeToNow(Instant instant) {
        if (instant == null) {
            return "<unset>";
        }
        long seconds = Duration.between(Instant.now(), instant).getSeconds();
        return instant + (seconds < 0 ? " (" + -seconds + "s ago)" : " (in " + seconds + "s)");
    }
}
