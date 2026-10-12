package com.conecta.authorization_api.authorization_api.service;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class ClientPolicyTests {
    private final InfrastructureClientService service = new InfrastructureClientService(mock(RegisteredClientRepository.class),
            mock(JdbcTemplate.class), mock(PasswordEncoder.class), mock(AuditService.class));

    @Test void nonLoopbackHttpIsRejected() {
        assertThatThrownBy(() -> service.create(new InfrastructureClientService.ClientSpec("client", "Client", true,
                List.of("http://example.com/callback"), List.of("openid"), false))).hasMessageContaining("HTTPS");
    }
    @Test void wildcardRedirectIsRejected() {
        assertThatThrownBy(() -> service.create(new InfrastructureClientService.ClientSpec("client", "Client", true,
                List.of("https://example.com/*"), List.of("openid"), false))).hasMessageContaining("exact");
    }
    @Test void machineClientCannotBePublic() {
        assertThatThrownBy(() -> service.create(new InfrastructureClientService.ClientSpec("client", "Client", true,
                List.of(), List.of("api.read"), true))).hasMessageContaining("confidential");
    }
    @Test void interactiveClientsRequireRedirects() {
        assertThatThrownBy(() -> service.create(new InfrastructureClientService.ClientSpec("client", "Client", true,
                List.of(), List.of("openid"), false))).hasMessageContaining("redirect");
    }
}
