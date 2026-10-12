package com.conecta.authorization_api.authorization_api.config;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import com.conecta.authorization_api.authorization_api.domain.Role;
import com.conecta.authorization_api.authorization_api.repository.IdentityRepository;
import com.conecta.authorization_api.authorization_api.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Configuration
public class InfrastructureBootstrapConfiguration {

    @Bean
    ApplicationRunner infrastructureBootstrap(
            IdentityRepository identities,
            RoleRepository roles,
            PasswordEncoder passwordEncoder,
            @Value("${app.bootstrap.infrastructure.username:}") String username,
            @Value("${app.bootstrap.infrastructure.email:}") String email,
            @Value("${app.bootstrap.infrastructure.password:}") String password) {
        return arguments -> createFirstOperator(identities, roles, passwordEncoder, username, email, password);
    }

    @Transactional
    void createFirstOperator(IdentityRepository identities, RoleRepository roles, PasswordEncoder passwordEncoder,
                             String username, String email, String password) {
        if (identities.findByUsernameAndRolesName(username, "INFRASTRUCTURE_INTERNAL").isPresent()) return;
        if (username.isBlank() && email.isBlank() && password.isBlank()) return;
        if (username.isBlank() || email.isBlank() || password.length() < 16) {
            throw new IllegalStateException("Infrastructure bootstrap requires username, email, and a 16+ character password");
        }
        Role role = roles.findByName("INFRASTRUCTURE_INTERNAL")
                .orElseThrow(() -> new IllegalStateException("INFRASTRUCTURE_INTERNAL role is not configured"));
        Identity identity = Identity.pendingRegistration(username, email, passwordEncoder.encode(password), Set.of(role));
        identity.activate();
        identities.save(identity);
    }
}
