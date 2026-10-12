package com.conecta.authorization_api.authorization_api.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.beans.factory.annotation.Value;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfiguration {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, SessionRegistry registry,
            @Value("${app.accounts.web-base-url:http://localhost:3000}") String webBaseUrl) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        authorizationServer.oidc(Customizer.withDefaults());
        http
                .securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(webBaseUrl + "/login")))
                .sessionManagement(session -> session.maximumSessions(-1).sessionRegistry(registry)
                        .expiredSessionStrategy(event -> event.getResponse().setStatus(401)));
        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthorizationProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.issuer())
                .build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(AuthorizationProperties properties) {
        RSAKey rsaKey = loadRsaKey(properties.keyStore());
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2RefreshTokenGenerator());
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (!"access_token".equals(context.getTokenType().getValue())) {
                return;
            }
            context.getClaims().claim("roles", context.getPrincipal().getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .sorted()
                    .toList());
        };
    }

    private RSAKey loadRsaKey(AuthorizationProperties.KeyStore properties) {
        if (properties.location() == null || properties.location().isBlank()) {
            throw new IllegalStateException("AUTHORIZATION_KEY_STORE must point to a PKCS12 keystore");
        }
        if (properties.password() == null || properties.password().isBlank()
                || properties.keyPassword() == null || properties.keyPassword().isBlank()) {
            throw new IllegalStateException("Keystore passwords must be configured");
        }

        try (var input = new java.net.URL(properties.location()).openStream()) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(input, properties.password().toCharArray());
            var key = keyStore.getKey(properties.alias(), properties.keyPassword().toCharArray());
            var certificate = keyStore.getCertificate(properties.alias());
            if (!(key instanceof RSAPrivateKey privateKey)
                    || certificate == null
                    || !(certificate.getPublicKey() instanceof RSAPublicKey publicKey)) {
                throw new IllegalStateException("Keystore alias must contain an RSA private key and certificate");
            }
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.nameUUIDFromBytes(certificate.getEncoded()).toString())
                    .build();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to load authorization-server signing key", exception);
        }
    }
}
