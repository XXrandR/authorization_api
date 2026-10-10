package com.conecta.authorization_api.authorization_api.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            AuthenticationProvider daoAuthenticationProvider
    ) throws Exception {

        PasswordGrantAuthenticationProvider passwordProvider =
                new PasswordGrantAuthenticationProvider(
                        daoAuthenticationProvider,
                        authorizationService,
                        tokenGenerator
                );

        http
                .oauth2AuthorizationServer(server ->
                        server
                                .tokenEndpoint(tokenEndpoint ->
                                        tokenEndpoint
                                                .accessTokenRequestConverter(
                                                        new PasswordGrantAuthenticationConverter()
                                                )
                                )
                                .tokenGenerator(tokenGenerator)
                )
                .authenticationProvider(passwordProvider);

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
