package com.conecta.authorization_api.authorization_api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
public class AuthorizationPersistenceConfiguration {

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository delegate = new JdbcRegisteredClientRepository(jdbcTemplate);
        return new RegisteredClientRepository() {
            public void save(org.springframework.security.oauth2.server.authorization.client.RegisteredClient client) { delegate.save(client); }
            public org.springframework.security.oauth2.server.authorization.client.RegisteredClient findById(String id) { return delegate.findById(id); }
            public org.springframework.security.oauth2.server.authorization.client.RegisteredClient findByClientId(String id) {
                Boolean enabled = jdbcTemplate.query("SELECT enabled FROM auth.oauth2_registered_client WHERE client_id = ?",
                        result -> result.next() && result.getBoolean(1), id);
                return Boolean.TRUE.equals(enabled) ? delegate.findByClientId(id) : null;
            }
        };
    }

    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService delegate = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        return new OAuth2AuthorizationService() {
            public void save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
                var previous = delegate.findById(authorization.getId());
                delegate.save(authorization);
                if (authorization.getAccessToken() != null && (previous == null || previous.getAccessToken() == null
                        || !previous.getAccessToken().getToken().getTokenValue().equals(authorization.getAccessToken().getToken().getTokenValue()))) {
                    jdbcTemplate.update("INSERT INTO auth.access_event (id, username, event_type) VALUES (?, ?, ?)",
                            java.util.UUID.randomUUID(), authorization.getPrincipalName(), previous != null && previous.getAccessToken() != null ? "TOKEN_REFRESHED" : "TOKEN_ISSUED");
                }
            }
            public void remove(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
                delegate.remove(authorization);
            }
            public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findById(String id) { return delegate.findById(id); }
            public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findByToken(String token, org.springframework.security.oauth2.server.authorization.OAuth2TokenType type) { return delegate.findByToken(token, type); }
        };
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
}
