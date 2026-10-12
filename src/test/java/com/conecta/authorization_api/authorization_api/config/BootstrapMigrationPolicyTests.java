package com.conecta.authorization_api.authorization_api.config;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class BootstrapMigrationPolicyTests {
    @Test void productionCannotUseLocalPassword() {
        assertThatThrownBy(() -> BootstrapMigrationPolicy.requireStrongPassword("admin1234"))
                .hasMessageContaining("INFRASTRUCTURE_ADMIN_PASSWORD");
    }
    @Test void strongDeploymentSecretIsAccepted() {
        assertThatCode(() -> BootstrapMigrationPolicy.requireStrongPassword("strong-deployment-secret-2026"))
                .doesNotThrowAnyException();
    }
}
