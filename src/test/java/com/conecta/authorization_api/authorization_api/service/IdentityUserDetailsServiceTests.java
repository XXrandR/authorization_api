package com.conecta.authorization_api.authorization_api.service;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import com.conecta.authorization_api.authorization_api.domain.Role;
import com.conecta.authorization_api.authorization_api.repository.IdentityRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityUserDetailsServiceTests {

    private final IdentityRepository repository = mock(IdentityRepository.class);
    private final IdentityUserDetailsService service = new IdentityUserDetailsService(repository);

    @Test
    void loadsAccountStateAndAuthoritiesFromIdentity() {
        Identity identity = new Identity();
        ReflectionTestUtils.setField(identity, "username", "alice");
        ReflectionTestUtils.setField(identity, "passwordHash", "{bcrypt}hash");
        ReflectionTestUtils.setField(identity, "active", true);
        ReflectionTestUtils.setField(identity, "blocked", false);

        Role role = new Role();
        ReflectionTestUtils.setField(role, "name", "ADMIN");
        ReflectionTestUtils.setField(identity, "roles", Set.of(role));
        when(repository.findByUsername("alice")).thenReturn(Optional.of(identity));

        var user = service.loadUserByUsername("alice");

        assertThat(user.getUsername()).isEqualTo("alice");
        assertThat(user.getPassword()).isEqualTo("{bcrypt}hash");
        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isAccountNonLocked()).isTrue();
        assertThat(user.getAuthorities()).extracting("authority").containsExactly("ADMIN");
    }

    @Test
    void rejectsUnknownIdentities() {
        when(repository.findByUsername("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("missing"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
