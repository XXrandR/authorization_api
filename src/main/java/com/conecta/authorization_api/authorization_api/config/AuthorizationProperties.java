package com.conecta.authorization_api.authorization_api.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "app.authorization")
public record AuthorizationProperties(
        String issuer,
        Cors cors,
        KeyStore keyStore
) {
    public record Cors(List<String> allowedOrigins) {
    }

    public record KeyStore(
            String location,
            String password,
            String alias,
            String keyPassword
    ) {
    }
}
