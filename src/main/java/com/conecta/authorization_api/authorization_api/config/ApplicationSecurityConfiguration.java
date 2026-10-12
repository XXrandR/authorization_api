package com.conecta.authorization_api.authorization_api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.http.HttpStatus;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ApplicationSecurityConfiguration {

    @Bean
    SessionRegistry sessionRegistry() { return new SessionRegistryImpl(); }

    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() { return new HttpSessionEventPublisher(); }

    @Bean
    RequestCache requestCache() {
        return new HttpSessionRequestCache();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationProvider daoAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    @Order(2)
    SecurityFilterChain applicationSecurityFilterChain(HttpSecurity http, JsonAuthenticationHandlers authenticationHandlers,
                                                      SessionRegistry sessionRegistry) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(
                                "/api/v1/security/csrf",
                                "/api/v1/session",
                                "/api/v1/accounts/registrations",
                                "/api/v1/accounts/email-verifications/**",
                                "/api/v1/accounts/password-resets/**"
                         ).permitAll()
                        .requestMatchers("/api/v1/infrastructure/**").hasAuthority("INFRASTRUCTURE_INTERNAL")
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler(authenticationHandlers.successHandler())
                        .failureHandler(authenticationHandlers.failureHandler()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                        PathPatternRequestMatcher.withDefaults().matcher("/api/**")))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/oauth2/token", "/oauth2/revoke"))
                .logout(logout -> logout.logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler((request, response, authentication) -> response.setStatus(204)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(-1).sessionRegistry(sessionRegistry)
                        .expiredSessionStrategy(event -> event.getResponse().setStatus(401)))
                .cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(AuthorizationProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(properties.cors().allowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With", "X-XSRF-TOKEN"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
