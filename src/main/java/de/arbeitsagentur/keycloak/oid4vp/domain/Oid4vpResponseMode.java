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

import org.keycloak.utils.StringUtil;

/** Models the OID4VP direct-post response modes used by the verifier. */
public enum Oid4vpResponseMode {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt");

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

    public static Oid4vpResponseMode resolve(String rawValue, boolean enforceHaip) {
        return enforceHaip ? DIRECT_POST_JWT : resolve(rawValue);
    }

    public static Oid4vpResponseMode resolve(String rawValue) {
        if (StringUtil.isBlank(rawValue)) {
            return DIRECT_POST;
        }
        for (Oid4vpResponseMode mode : values()) {
            if (mode.parameterValue.equalsIgnoreCase(rawValue)) {
                return mode;
            }
        }
        return DIRECT_POST;
    }
}
