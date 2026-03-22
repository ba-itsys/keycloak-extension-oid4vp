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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.oid4vp.domain.PreparedDcqlQuery;
import de.arbeitsagentur.keycloak.oid4vp.util.Oid4vpMapperConfigProperties;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

class Oid4vpIdentityProviderTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private Oid4vpIdentityProvider provider;
    private Oid4vpIdentityProviderConfig config;
    private AuthenticationSessionModel authSession;
    private LoginFormsProvider forms;
    private KeycloakContext context;
    private SingleUseObjectProvider singleUseObjects;
    private RealmModel realm;

    @BeforeEach
    void setUp() {
        KeycloakSession session = mock(KeycloakSession.class);
        context = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getAccessCodeLifespanLogin()).thenReturn(300);
        when(context.getRealm()).thenReturn(realm);
        when(session.getContext()).thenReturn(context);
        singleUseObjects = mock(SingleUseObjectProvider.class);
        when(session.singleUseObjects()).thenReturn(singleUseObjects);

        forms = mock(LoginFormsProvider.class);
        Response response = Response.ok("login-form").build();
        when(session.getProvider(LoginFormsProvider.class)).thenReturn(forms);
        when(forms.setAuthenticationSession(any())).thenReturn(forms);
        when(forms.setAttribute(any(), any())).thenReturn(forms);
        when(forms.createForm("login-oid4vp-idp.ftl")).thenReturn(response);

        config = new Oid4vpIdentityProviderConfig();
        config.setAlias("oid4vp");
        config.setSameDeviceEnabled(false);
        config.setCrossDeviceEnabled(false);
        config.setEnforceHaip(false);

        provider = new Oid4vpIdentityProvider(session, config);
        authSession = mock(AuthenticationSessionModel.class);
    }

    @Test
    void performLogin_keepsClientIdentifiersInLoginContextInsteadOfAuthNotes() {
        AuthenticationRequest request = mock(AuthenticationRequest.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(request.getRealm()).thenReturn(realm);
        when(request.getAuthenticationSession()).thenReturn(authSession);
        when(request.getRedirectUri()).thenReturn("http://localhost:8080/callback");

        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://localhost:8080/"));
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(request.getUriInfo()).thenReturn(uriInfo);

        Response response = provider.performLogin(request);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(authSession, never()).setAuthNote(anyString(), any());
    }

    @Test
    void buildDcqlQueryFromConfig_manualSdJwtBackfillsMetaAndTrustedAuthorities() throws Exception {
        config.setDcqlQuery("""
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "claims": [
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """);
        config.setTrustListUrl("https://trust-list.example.com/tl.jwt");
        config.setTrustedAuthoritiesMode("etsi_tl");

        Map<String, Object> dcql = parseDcql(provider.buildDcqlQueryFromConfig());
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credential.get("meta");

        assertThat(meta.get("vct_values")).isEqualTo(List.of("pid"));
        assertThat(credential.get("trusted_authorities"))
                .isEqualTo(
                        List.of(Map.of("type", "etsi_tl", "values", List.of("https://trust-list.example.com/tl.jwt"))));
    }

    @Test
    void buildDcqlQueryFromConfig_manualMdocBackfillsDoctype() throws Exception {
        config.setDcqlQuery("""
                {
                  "credentials": [
                    {
                      "id": "org.iso.18013.5.1.mDL",
                      "format": "mso_mdoc",
                      "claims": [
                        { "path": ["org.iso.18013.5.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """);

        Map<String, Object> dcql = parseDcql(provider.buildDcqlQueryFromConfig());
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) credential.get("meta");

        assertThat(meta.get("doctype_value")).isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void prepareDcqlQueryFromConfig_manualQuery_extractsConfiguredCredentialTypesFromNormalizedQuery() {
        config.setDcqlQuery("""
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "claims": [
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """);

        PreparedDcqlQuery prepared = provider.prepareDcqlQueryFromConfig();

        assertThat(prepared.configuredCredentialTypes()).containsExactly("pid");
    }

    @Test
    void buildDcqlQueryFromConfig_manualQueryWithoutTrustedAuthoritiesFlags_doesNotInjectThem() throws Exception {
        config.setDcqlQuery("""
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "claims": [
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """);
        config.setTrustListUrl("https://trust-list.example.com/tl.jwt");
        config.setTrustedAuthoritiesMode("none");

        Map<String, Object> dcql = parseDcql(provider.buildDcqlQueryFromConfig());
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);

        assertThat(credential).doesNotContainKey("trusted_authorities");
    }

    @Test
    void buildDcqlQueryFromConfig_transientUsersEnabled_doesNotAddIdentifyingClaim() throws Exception {
        IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
        mapper.setConfig(new LinkedHashMap<>());
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "IdentityCredential");
        mapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "given_name");
        when(realm.getIdentityProviderMappersByAliasStream("oid4vp")).thenReturn(java.util.stream.Stream.of(mapper));

        config.setUserMappingClaim("sub");
        config.setTransientUsersEnabled(true);

        Map<String, Object> dcql = parseDcql(provider.buildDcqlQueryFromConfig());
        @SuppressWarnings("unchecked")
        Map<String, Object> credential = ((List<Map<String, Object>>) dcql.get("credentials")).get(0);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> claims = (List<Map<String, Object>>) credential.get("claims");

        assertThat(claims).extracting(claim -> claim.get("path")).containsExactly(List.of("given_name"));
    }

    @Test
    void prepareDcqlQueryFromConfig_mapperGeneratedQuery_usesMapperTypesWithoutParsingBuiltJson() {
        IdentityProviderMapperModel sdJwtMapper = new IdentityProviderMapperModel();
        sdJwtMapper.setConfig(new LinkedHashMap<>());
        sdJwtMapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "IdentityCredential");
        sdJwtMapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "given_name");

        IdentityProviderMapperModel mdocMapper = new IdentityProviderMapperModel();
        mdocMapper.setConfig(new LinkedHashMap<>());
        mdocMapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_FORMAT, "mso_mdoc");
        mdocMapper.getConfig().put(Oid4vpMapperConfigProperties.CREDENTIAL_TYPE, "eu.europa.ec.eudi.pid.1");
        mdocMapper.getConfig().put(Oid4vpMapperConfigProperties.CLAIM_PATH, "family_name");

        when(realm.getIdentityProviderMappersByAliasStream("oid4vp"))
                .thenReturn(java.util.stream.Stream.of(sdJwtMapper, mdocMapper));

        PreparedDcqlQuery prepared = provider.prepareDcqlQueryFromConfig();

        assertThat(prepared.dcqlQuery()).contains("\"credentials\"");
        assertThat(prepared.configuredCredentialTypes())
                .containsExactly("IdentityCredential", "eu.europa.ec.eudi.pid.1");
    }

    @Test
    void performLogin_usesSameDeviceHandleForFormAndCrossDeviceHandleForSse() {
        config.setSameDeviceEnabled(true);
        config.setCrossDeviceEnabled(true);

        AuthenticationRequest request = mock(AuthenticationRequest.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(request.getRealm()).thenReturn(realm);
        when(request.getAuthenticationSession()).thenReturn(authSession);
        when(request.getRedirectUri()).thenReturn("http://localhost:8080/callback");

        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(uriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://localhost:8080/"));
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(request.getUriInfo()).thenReturn(uriInfo);
        when(context.getUri()).thenReturn(uriInfo);

        provider.performLogin(request);

        verify(forms, times(1)).setAttribute(eq("requestHandle"), any());
        verify(forms, times(1)).setAttribute(eq("crossDeviceRequestHandle"), any());
    }

    @Test
    void performLogin_usesAuthSessionTabForFlowBindingAndRequestTabForBrowserRouting() {
        config.setSameDeviceEnabled(true);

        AuthenticationRequest request = mock(AuthenticationRequest.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(request.getRealm()).thenReturn(realm);
        when(request.getAuthenticationSession()).thenReturn(authSession);
        when(request.getRedirectUri()).thenReturn("http://localhost:8080/callback");
        when(authSession.getTabId()).thenReturn("auth-tab");

        MultivaluedHashMap<String, String> queryParams = new MultivaluedHashMap<>();
        queryParams.putSingle("tab_id", "request-tab");
        queryParams.putSingle("session_code", "session-code");
        queryParams.putSingle("client_data", "client-data");

        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(uriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://localhost:8080/"));
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(request.getUriInfo()).thenReturn(uriInfo);
        when(context.getUri()).thenReturn(uriInfo);

        provider.performLogin(request);

        verify(singleUseObjects).put(startsWith("oid4vp_request_handle:"), anyLong(), argThat(values -> "auth-tab"
                .equals(values.get("tabId"))));
        verify(forms)
                .setAttribute(
                        eq("state"),
                        argThat(value -> value instanceof String && ((String) value).startsWith("auth-tab.")));
        verify(forms)
                .setAttribute(
                        eq("formActionUrl"),
                        argThat(value -> value instanceof String && ((String) value).contains("tab_id=request-tab")));
    }

    @Test
    void performLogin_storesFlowTypeInFlowHandleAndKeepsResponseUriStable() {
        config.setCrossDeviceEnabled(true);

        AuthenticationRequest request = mock(AuthenticationRequest.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(request.getRealm()).thenReturn(realm);
        when(request.getAuthenticationSession()).thenReturn(authSession);
        when(request.getRedirectUri()).thenReturn("http://localhost:8080/callback");
        when(authSession.getTabId()).thenReturn("auth-tab");

        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        when(uriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://localhost:8080/"));
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(request.getUriInfo()).thenReturn(uriInfo);
        when(context.getUri()).thenReturn(uriInfo);

        provider.performLogin(request);

        verify(singleUseObjects)
                .put(
                        startsWith("oid4vp_request_handle:"),
                        anyLong(),
                        argThat(values -> "cross_device".equals(values.get("flow"))
                                && "http://localhost:8080/realms/test-realm/broker/oid4vp/endpoint"
                                        .equals(values.get("responseUri"))));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseDcql(String dcqlJson) throws Exception {
        return OBJECT_MAPPER.readValue(dcqlJson, Map.class);
    }
}
