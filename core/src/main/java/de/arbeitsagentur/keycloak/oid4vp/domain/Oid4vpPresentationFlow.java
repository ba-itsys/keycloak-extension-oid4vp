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
package de.arbeitsagentur.keycloak.oid4vp.domain;

/**
 * How the presentation reached the verifier: from the wallet on the device the browser session
 * runs on, or from a wallet on another device that scanned the QR code. The flow of a completed
 * login is exposed to the identity provider mappers.
 */
public enum Oid4vpPresentationFlow {
    SAME_DEVICE(Oid4vpConstants.FLOW_SAME_DEVICE),
    CROSS_DEVICE(Oid4vpConstants.FLOW_CROSS_DEVICE);

    private final String value;

    Oid4vpPresentationFlow(String value) {
        this.value = value;
    }

    /** The wire value of the flow, as the request context records it. */
    public String value() {
        return value;
    }

    /** The flow carrying the given wire value, or null for an unknown or absent value. */
    public static Oid4vpPresentationFlow of(String value) {
        for (Oid4vpPresentationFlow flow : values()) {
            if (flow.value.equals(value)) {
                return flow;
            }
        }
        return null;
    }
}
