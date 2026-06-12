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
package de.arbeitsagentur.keycloak.oid4vp.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.oid4vp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.conformance.containers.OpenIdConformanceSuite;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceApiClient;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceModuleVariant;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ConformanceResult;
import de.arbeitsagentur.keycloak.oid4vp.conformance.runner.ModuleRun;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.CredentialProfile;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.KeycloakVerifierBrowser;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.TrustListServer;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.VerifierScenario;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.VerifierSigningMaterial;
import de.arbeitsagentur.keycloak.oid4vp.conformance.verifier.VerifierSuiteConfig;
import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.keycloak.common.Profile;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.util.JsonSerialization;

/**
 * Base class for the OID4VP verifier conformance modules. Each subclass targets one module and
 * runs it across every spec relevant variant combination the provider supports. Keycloak is
 * reconfigured per variant before the module runs.
 */
public abstract class AbstractVerifierConformanceTest extends AbstractConformanceTest {

    static final String IDP_ALIAS = "oid4vp";

    private static final String FINAL_PLAN = "oid4vp-1final-verifier-test-plan";
    private static final String HAIP_PLAN = "oid4vp-1final-verifier-haip-test-plan";

    @InjectRealm(config = VerifierConformanceRealmConfig.class)
    protected ManagedRealm realm;

    @InjectKeycloakUrls
    protected KeycloakUrls keycloakUrls;

    // Suite declared variant dimension values. The provider supports only the x509 client
    // identifier prefixes, so redirect_uri is excluded as a provider capability. Every other
    // combination is enumerated and the suite decides applicability during discovery.
    private static final List<String> CREDENTIAL_FORMATS = List.of("sd_jwt_vc", "iso_mdl");
    private static final List<String> CLIENT_ID_PREFIXES = List.of("x509_san_dns", "x509_hash");
    private static final List<String> REQUEST_METHODS = List.of("url_query", "request_uri_signed");
    private static final List<String> RESPONSE_MODES = List.of("direct_post", "direct_post.jwt");

    // Modules and their variants discovered from the suite, keyed by plan + plan variant
    private static final Map<PlanVariant, List<ConformanceApiClient.DiscoveredModule>> DISCOVERED =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static volatile boolean discovered;

    private record PlanVariant(String plan, Map<String, String> variant) {}

    /**
     * Discovers every module and module variant the suite offers for one module name across all
     * enumerated plan variants. Combinations are not fabricated: the suite reports which modules
     * and variants apply, and inapplicable plan variants yield nothing.
     */
    protected Stream<ConformanceModuleVariant> verifierModuleVariants(
            String moduleName, ConformanceResult expectedResult) {
        ensureDiscovered();
        return DISCOVERED.entrySet().stream().flatMap(entry -> entry.getValue().stream()
                .filter(module -> module.name().equals(moduleName))
                .map(module -> new ConformanceModuleVariant(
                        entry.getKey().plan(),
                        entry.getKey().variant(),
                        module.name(),
                        module.variant(),
                        expectedResult)));
    }

    private static synchronized void ensureDiscovered() {
        if (discovered) {
            return;
        }
        ConformanceApiClient client = OpenIdConformanceSuite.instance().client();
        discoverNonHaipProfile(client);
        discoverHaipProfile(client);
        discovered = true;
    }

    /**
     * Non-HAIP profile: the final verifier plan run with vp_profile=plain_vp (the suite defaults
     * vp_profile to haip, which would exclude the unencrypted direct_post response mode the
     * provider also supports). Crosses every verifier identification and response delivery
     * dimension; the suite filters the combinations it does not support, such as url_query with an
     * x509 client identifier prefix.
     */
    private static void discoverNonHaipProfile(ConformanceApiClient client) {
        for (String format : CREDENTIAL_FORMATS) {
            for (String clientIdPrefix : CLIENT_ID_PREFIXES) {
                for (String requestMethod : REQUEST_METHODS) {
                    for (String responseMode : RESPONSE_MODES) {
                        Map<String, String> planVariant = new LinkedHashMap<>();
                        planVariant.put("vp_profile", "plain_vp");
                        planVariant.put("credential_format", format);
                        planVariant.put("client_id_prefix", clientIdPrefix);
                        planVariant.put("request_method", requestMethod);
                        planVariant.put("response_mode", responseMode);
                        discover(client, FINAL_PLAN, planVariant);
                    }
                }
            }
        }
    }

    /**
     * HAIP profile: the dedicated HAIP verifier plan, which pins the x509_hash client identifier
     * prefix, signed requests and the haip profile. Only the credential format and response mode
     * vary.
     */
    private static void discoverHaipProfile(ConformanceApiClient client) {
        for (String format : CREDENTIAL_FORMATS) {
            for (String responseMode : RESPONSE_MODES) {
                Map<String, String> planVariant = new LinkedHashMap<>();
                planVariant.put("credential_format", format);
                planVariant.put("response_mode", responseMode);
                discover(client, HAIP_PLAN, planVariant);
            }
        }
    }

    private static void discover(ConformanceApiClient client, String plan, Map<String, String> planVariant) {
        VerifierScenario scenario = VerifierScenario.fromVariant(plan, planVariant);
        List<ConformanceApiClient.DiscoveredModule> modules =
                client.discoverPlanModules(plan, planVariant, suiteConfigFor(scenario));
        if (!modules.isEmpty()) {
            DISCOVERED.put(new PlanVariant(plan, planVariant), modules);
        }
    }

    @Override
    protected void prepareModule(ConformanceModuleVariant moduleVariant) {
        VerifierScenario scenario = VerifierScenario.fromVariant(moduleVariant.plan(), moduleVariant.planVariant());
        boolean exists =
                realm.admin().identityProviders().findAll().stream().anyMatch(idp -> IDP_ALIAS.equals(idp.getAlias()));
        if (exists) {
            realm.admin().identityProviders().get(IDP_ALIAS).remove();
        }
        try (Response response = realm.admin().identityProviders().create(identityProvider(scenario))) {
            Assertions.assertEquals(
                    201, response.getStatus(), "Creating the OID4VP identity provider failed: " + body(response));
        }
        for (IdentityProviderMapperRepresentation mapper : scenario.profile().mappers()) {
            mapper.setIdentityProviderAlias(IDP_ALIAS);
            try (Response response =
                    realm.admin().identityProviders().get(IDP_ALIAS).addMapper(mapper)) {
                Assertions.assertEquals(
                        201, response.getStatus(), "Creating identity provider mapper " + mapper.getName() + " failed");
            }
        }
    }

    @Override
    protected void interact(ConformanceModuleVariant moduleVariant, ModuleRun moduleRun) {
        VerifierScenario scenario = VerifierScenario.fromVariant(moduleVariant.plan(), moduleVariant.planVariant());
        KeycloakVerifierBrowser browser = new KeycloakVerifierBrowser(suite, keycloakUrls.getBase());
        KeycloakVerifierBrowser.AuthorizationRequest request = browser.fetchSameDeviceAuthorizationRequest(
                VerifierConformanceRealmConfig.REALM, VerifierConformanceRealmConfig.CLIENT_ID, IDP_ALIAS);
        assertAuthorizationRequestMatchesScenario(scenario, request);
        browser.triggerAuthorization(moduleRun, request);
    }

    @Override
    protected JsonNode suiteConfig(ConformanceModuleVariant moduleVariant) {
        return suiteConfigFor(VerifierScenario.fromVariant(moduleVariant.plan(), moduleVariant.planVariant()));
    }

    private static JsonNode suiteConfigFor(VerifierScenario scenario) {
        VerifierSigningMaterial material = signingMaterial();
        // The verifier strips the self-signed trust anchor from the x5c chain per HAIP, so the
        // suite is given the trust anchor out of band to validate the request object chain.
        return VerifierSuiteConfig.create(
                        "keycloak-oid4vp-" + UUID.randomUUID(),
                        rawClientId(scenario),
                        material.caCertPem(),
                        JsonSerialization.valueFromString(material.jwkJson(), JsonNode.class))
                .toJson();
    }

    private void assertAuthorizationRequestMatchesScenario(
            VerifierScenario scenario, KeycloakVerifierBrowser.AuthorizationRequest request) {
        String expectedClientId = scenario.clientIdScheme() + ":" + rawClientId(scenario);
        Assertions.assertEquals(expectedClientId, request.clientId(), "Unexpected wallet link client_id");
        Assertions.assertEquals(
                expectedClientId,
                request.requestObjectClaims().path("client_id").asText(),
                "Unexpected request object client_id");
    }

    private static String rawClientId(VerifierScenario scenario) {
        return "x509_san_dns".equals(scenario.clientIdScheme())
                ? OpenIdConformanceSuite.KEYCLOAK_BASE_URI.getHost()
                : signingMaterial().x509Hash();
    }

    private static VerifierSigningMaterial signingMaterial() {
        return VerifierSigningMaterial.forHost(OpenIdConformanceSuite.KEYCLOAK_BASE_URI.getHost());
    }

    private IdentityProviderRepresentation identityProvider(VerifierScenario scenario) {
        VerifierSigningMaterial material = signingMaterial();
        List<String> trustedCertificates = new ArrayList<>(List.of(material.leafCertPem(), material.caCertPem()));
        if (scenario.profile().includeMdlIssuer()) {
            trustedCertificates.add(CredentialProfile.MDL_ISSUER_CERTIFICATE_PEM);
        }
        String trustListUrl =
                TrustListServer.instance().publish("trustlist-" + getClass().getSimpleName(), trustedCertificates);

        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(IDP_ALIAS);
        idp.setDisplayName("Sign in with Wallet");
        idp.setProviderId(Oid4vpConstants.PROVIDER_ID);
        idp.setEnabled(true);
        idp.setFirstBrokerLoginFlowAlias("first broker login");

        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "not-used");
        config.put("clientSecret", "not-used");
        config.put(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, scenario.clientIdScheme());
        config.put(Oid4vpIdentityProviderConfig.RESPONSE_MODE, scenario.responseMode());
        config.put(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, String.valueOf(scenario.enforceHaip()));
        config.put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, "true");
        config.put(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, "false");
        config.put(Oid4vpIdentityProviderConfig.TRUSTED_AUTHORITIES_MODE, "none");
        config.put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "0");
        config.put(Oid4vpIdentityProviderConfig.TRUST_LIST_URL, trustListUrl);
        config.put(Oid4vpIdentityProviderConfig.TRUST_LIST_LOTE_TYPE, TrustListServer.PID_LOTE_TYPE);
        config.put(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, material.combinedPem());
        config.put(
                Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM,
                scenario.profile().userMappingClaim());
        config.put(
                Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC,
                scenario.profile().userMappingClaimMdoc());
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, scenario.profile().dcqlQuery());
        idp.setConfig(config);
        return idp;
    }

    private static String body(Response response) {
        return response.readEntity(String.class);
    }

    public static class VerifierServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.dependency("de.arbeitsagentur.opdt", "keycloak-extension-oid4vp", true)
                    // Runtime dependency of the provider, shaded into the provider jar for production
                    .dependency("com.authlete", "cbor")
                    .features(Profile.Feature.TRANSIENT_USERS)
                    .option("hostname", OpenIdConformanceSuite.KEYCLOAK_BASE_URI.toString());
        }
    }
}
