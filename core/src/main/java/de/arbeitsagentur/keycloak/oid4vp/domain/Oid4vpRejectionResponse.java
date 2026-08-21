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

import org.jboss.logging.Logger;
import org.keycloak.utils.StringUtil;

/**
 * How the response URI answers a presentation this verifier rejected. OID4VP 1.0 §8.2 ties HTTP 200
 * to the Response URI having "successfully processed" the response without defining the term, so
 * both answers are conformant and the OID4VP conformance suite accepts either.
 *
 * <p>A wallet-reported error response (§8.5) is not covered by this: the response URI processed it
 * whatever the wallet reported, so it is always answered like a completed login.
 */
public enum Oid4vpRejectionResponse {

    /**
     * HTTP 200 and the {@code redirect_uri} that hands the End-User back, the way a completed login
     * is answered. A wallet reads the status before the body, so this is what makes it follow the
     * redirect instead of showing an error of its own and stranding the End-User.
     */
    REDIRECT("redirect"),

    /**
     * HTTP 400 with {@code error} and {@code error_description} beside the {@code redirect_uri}.
     * The rejection is visible to the wallet, and the OID4VP conformance suite's negative verifier
     * modules finish PASSED rather than REVIEW, at the cost of wallets that abort on a non-2xx
     * status never following the redirect.
     */
    ERROR("error");

    private static final Logger LOG = Logger.getLogger(Oid4vpRejectionResponse.class);

    private final String configValue;

    Oid4vpRejectionResponse(String configValue) {
        this.configValue = configValue;
    }

    public String configValue() {
        return configValue;
    }

    public boolean isError() {
        return this == ERROR;
    }

    /** The configured answer, defaulting to {@link #REDIRECT}. */
    public static Oid4vpRejectionResponse resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return REDIRECT;
        }
        for (Oid4vpRejectionResponse response : values()) {
            if (response.configValue.equalsIgnoreCase(rawValue)) {
                return response;
            }
        }
        LOG.warnf("Unknown rejection response '%s' configured; using %s", rawValue, REDIRECT.configValue);
        return REDIRECT;
    }
}
