package com.conecta.authorization_api.authorization_api.service;

import com.conecta.authorization_api.authorization_api.domain.*;
import com.conecta.authorization_api.authorization_api.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class InfrastructureLifecycleTests {
    private final IdentityRepository identities = mock(IdentityRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final AuditService audit = mock(AuditService.class);
    private final AccessRevocationService revocation = mock(AccessRevocationService.class);
    private final InfrastructureOperationsService service = new InfrastructureOperationsService(identities, roles,
            mock(InvitationRepository.class), jdbc, mock(AccountNotificationService.class), audit, revocation,
            mock(SessionRegistry.class), mock(PasswordEncoder.class));
    private Identity identity;
    private final UUID id = UUID.randomUUID();

    @BeforeEach
    void setup() {
        identity = Identity.pendingRegistration("alice", "alice@example.com", "hash", Set.of(Role.custom("USER")));
        ReflectionTestUtils.setField(identity, "id", id);
        identity.activate();
        when(identities.findById(id)).thenReturn(Optional.of(identity));
    }

    @Test void reactivationWorks() {
        identity.deactivate();
        service.updateIdentity(id, "alice", "new@example.com", true);
        assertThat(identity.isActive()).isTrue();
        verify(revocation).revokeUser("alice");
        verify(audit).record("IDENTITY_UPDATED", "IDENTITY", id.toString());
    }
    @Test void usernamesAreImmutable() {
        assertThatThrownBy(() -> service.updateIdentity(id, "bob", "alice@example.com", true)).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(revocation);
    }
    @Test void blockingRevokesAllAccess() {
        service.block(id, true);
        assertThat(identity.isBlocked()).isTrue();
        verify(revocation).revokeUser("alice");
    }
    @Test void roleReplacementRevokesExistingAccess() {
        Role role = Role.custom("READER");
        when(roles.findByName("READER")).thenReturn(Optional.of(role));
        service.replaceRoles(id, Set.of("READER"));
        assertThat(identity.getRoles()).containsExactly(role);
        verify(revocation).revokeUser("alice");
    }
    @Test void lastOperatorCannotBeBlocked() {
        identity.replaceRoles(Set.of(Role.custom("INFRASTRUCTURE_INTERNAL")));
        when(jdbc.queryForObject(anyString(), eq(Long.class))).thenReturn(1L);
        assertThatThrownBy(() -> service.block(id, true)).hasMessageContaining("last active");
        verifyNoInteractions(revocation);
    }
    @Test void systemRolesCannotBeDeleted() {
        Role role = Role.custom("USER");
        ReflectionTestUtils.setField(role, "system", true);
        when(roles.findById(id)).thenReturn(Optional.of(role));
        assertThatThrownBy(() -> service.deleteRole(id)).hasMessageContaining("System roles");
        verify(roles, never()).delete(any());
    }
    @Test void assignedRolesCannotBeDeleted() {
        when(roles.findById(id)).thenReturn(Optional.of(Role.custom("READER")));
        when(jdbc.queryForObject(anyString(), eq(Integer.class), eq(id))).thenReturn(1);
        assertThatThrownBy(() -> service.deleteRole(id)).hasMessageContaining("Reassign members");
    }
    @Test void deletingIdentityRevokesAccessAndAudits() {
        service.deleteIdentity(id);
        verify(revocation).revokeUser("alice");
        verify(identities).delete(identity);
        verify(audit).record("IDENTITY_DELETED", "IDENTITY", id.toString());
    }
}
