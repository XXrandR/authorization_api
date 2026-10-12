package com.conecta.authorization_api.authorization_api.config;

import org.springframework.boot.flyway.autoconfigure.FlywayConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import java.util.HashMap;

@Configuration
public class BootstrapMigrationPolicy {
    @Bean
    FlywayConfigurationCustomizer bootstrapPlaceholders(Environment environment) {
        return configuration -> {
            var placeholders = new HashMap<>(configuration.getPlaceholders());
            String password = placeholders.getOrDefault("infrastructure_admin_password", "");
            if (!environment.acceptsProfiles(Profiles.of("local", "test"))) {
                requireStrongPassword(password);
            }
            // These placeholders occur inside PostgreSQL string literals. Escape
            // quotes so a deployment secret cannot accidentally become SQL.
            for (String name : java.util.List.of("infrastructure_admin_username", "infrastructure_admin_email", "infrastructure_admin_password")) {
                String value = placeholders.get(name);
                if (value != null) placeholders.put(name, value.replace("'", "''"));
            }
            configuration.placeholders(placeholders);
        };
    }

    static void requireStrongPassword(String password) {
        if (password.length() < 16 || password.equals("admin1234")) {
            throw new IllegalStateException("Set INFRASTRUCTURE_ADMIN_PASSWORD to a strong 16+ character secret outside the local profile");
        }
    }
}
