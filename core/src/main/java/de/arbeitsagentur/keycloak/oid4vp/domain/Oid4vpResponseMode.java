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

/** The OID4VP direct post response modes the verifier supports. */
public enum Oid4vpResponseMode {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt");

    private static final Logger LOG = Logger.getLogger(Oid4vpResponseMode.class);

    private final String parameterValue;

    Oid4vpResponseMode(String parameterValue) {
        this.parameterValue = parameterValue;
    }

    public String parameterValue() {
        return parameterValue;
    }

    public boolean requiresEncryption() {
        return this == DIRECT_POST_JWT;
    }

    /**
     * Resolves the configured response mode, defaulting to the encrypted one. An unrecognized
     * value can only come from scripted or imported configuration, and falling back to the default
     * silently changes the wire behavior, so it is warned about.
     */
    public static Oid4vpResponseMode resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return DIRECT_POST_JWT;
        }
        for (Oid4vpResponseMode mode : values()) {
            if (mode.parameterValue.equalsIgnoreCase(rawValue)) {
                return mode;
            }
        }
        LOG.warnf("Unknown response mode '%s' configured; using %s", rawValue, DIRECT_POST_JWT.parameterValue);
        return DIRECT_POST_JWT;
    }
}
