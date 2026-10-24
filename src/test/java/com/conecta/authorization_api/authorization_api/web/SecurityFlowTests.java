package com.conecta.authorization_api.authorization_api.web;

import com.conecta.authorization_api.authorization_api.config.*;
import com.conecta.authorization_api.authorization_api.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.beans.factory.annotation.Autowired;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Isolated HTTP/security integration tests: never connect to the developer database. */
@SpringJUnitConfig(SecurityFlowTests.TestApplication.class)
@WebAppConfiguration
class SecurityFlowTests {
    @Autowired WebApplicationContext context;
    @Autowired ObjectMapper mapper;
    private MockMvc mvc;

    @BeforeEach void setup() { mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build(); }

    @Test void unknownUserDoesNotAuthenticate() throws Exception {
        mvc.perform(post("/api/auth/login").with(csrf()).param("username", "unknown").param("password", "incorrect"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.authenticated").value(false));
    }
    @Test void validOperatorGetsAdminRedirectAndSession() throws Exception {
        var login = mvc.perform(post("/api/auth/login").with(csrf()).param("username", "operator").param("password", "correct-password-123"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.redirectUrl").value("/admin")).andReturn();
        mvc.perform(get("/api/v1/session").session((MockHttpSession) login.getRequest().getSession()))
                .andExpect(jsonPath("$.authenticated").value(true)).andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.hasItem("INFRASTRUCTURE_INTERNAL")));
    }
    @Test void apiDistinguishesAnonymousAndNonAdmin() throws Exception {
        mvc.perform(get("/api/v1/infrastructure/roles")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/infrastructure/roles").with(user("alice").authorities(() -> "USER"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/infrastructure/roles").with(user("operator").authorities(() -> "INFRASTRUCTURE_INTERNAL"))).andExpect(status().isOk());
    }
    @Test void adminMutationsRequireCsrf() throws Exception {
        mvc.perform(post("/api/v1/infrastructure/roles").with(user("operator").authorities(() -> "INFRASTRUCTURE_INTERNAL"))
                .contentType("application/json").content("{\"name\":\"READER\"}")).andExpect(status().isForbidden());
    }
    @Test void authorizationCodePkceRefreshAndRevocation() throws Exception {
        String verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO";
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        var authorize = mvc.perform(get("/oauth2/authorize").with(user("alice").authorities(() -> "USER"))
                .queryParam("response_type", "code").queryParam("client_id", "bff-test").queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("scope", "api.read").queryParam("state", "test-state").queryParam("code_challenge", challenge).queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection()).andReturn();
        String location = authorize.getResponse().getHeader("Location");
        assertThat(location).contains("code=");
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        var issued = mvc.perform(post("/oauth2/token").with(httpBasic("bff-test", "client-secret"))
                .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", "https://client.example/callback")
                .param("code_verifier", verifier)).andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").exists()).andReturn();
        String refresh = mapper.readTree(issued.getResponse().getContentAsString()).get("refresh_token").asText();
        var refreshed = mvc.perform(post("/oauth2/token").with(httpBasic("bff-test", "client-secret"))
                .param("grant_type", "refresh_token").param("refresh_token", refresh)).andExpect(status().isOk()).andReturn();
        String rotated = mapper.readTree(refreshed.getResponse().getContentAsString()).get("refresh_token").asText();
        assertThat(rotated).isNotEqualTo(refresh);
        mvc.perform(post("/oauth2/token").with(httpBasic("bff-test", "client-secret")).param("grant_type", "refresh_token").param("refresh_token", refresh))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/oauth2/revoke").with(httpBasic("bff-test", "client-secret")).param("token", rotated)).andExpect(status().isOk());
        mvc.perform(post("/oauth2/token").with(httpBasic("bff-test", "client-secret")).param("grant_type", "refresh_token").param("refresh_token", rotated))
                .andExpect(status().isBadRequest());
    }

    @Configuration
    @EnableWebMvc
    @Import({ApplicationSecurityConfiguration.class, AuthorizationServerConfiguration.class, JsonAuthenticationHandlers.class,
            SessionController.class, InfrastructureOperationsController.class})
    static class TestApplication {
        @Bean ObjectMapper mapper() { return new ObjectMapper(); }
        @Bean InfrastructureOperationsService operations() { return mock(InfrastructureOperationsService.class); }
        @Bean AdminQueryService queries() { return mock(AdminQueryService.class); }
        @Bean UserDetailsService users() {
            String hash = new BCryptPasswordEncoder().encode("correct-password-123");
            return username -> {
                if (!Set.of("operator", "alice").contains(username)) throw new org.springframework.security.core.userdetails.UsernameNotFoundException("Unknown user");
                return User.withUsername(username).password(hash).authorities(username.equals("operator") ? "INFRASTRUCTURE_INTERNAL" : "USER").build();
            };
        }
        @Bean RegisteredClientRepository clients() {
            return new InMemoryRegisteredClientRepository(RegisteredClient.withId(UUID.randomUUID().toString()).clientId("bff-test")
                    .clientSecret(new BCryptPasswordEncoder().encode("client-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://client.example/callback").scope("api.read")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                    .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build()).build());
        }
        @Bean OAuth2AuthorizationService authorizations() { return new InMemoryOAuth2AuthorizationService(); }
        @Bean OAuth2AuthorizationConsentService consents() { return new InMemoryOAuth2AuthorizationConsentService(); }
        @Bean AuthorizationProperties properties() throws Exception {
            Path directory = Files.createTempDirectory("security-test-");
            Path key = directory.resolve("signing.p12");
            Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                    "-genkeypair", "-alias", "authorization-server", "-keyalg", "RSA", "-storetype", "PKCS12", "-keystore", key.toString(),
                    "-storepass", "test-password", "-keypass", "test-password", "-dname", "CN=Test", "-validity", "1").redirectErrorStream(true).start();
            if (!process.waitFor(20, TimeUnit.SECONDS) || process.exitValue() != 0) throw new IllegalStateException("Unable to generate test signing key");
            key.toFile().deleteOnExit(); directory.toFile().deleteOnExit();
            return new AuthorizationProperties("http://localhost", new AuthorizationProperties.Cors(List.of("http://localhost:3000")),
                    new AuthorizationProperties.KeyStore(key.toUri().toString(), "test-password", "authorization-server", "test-password"));
        }
    }
}
