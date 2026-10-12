package com.conecta.authorization_api.authorization_api.service;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import com.conecta.authorization_api.authorization_api.domain.Invitation;
import com.conecta.authorization_api.authorization_api.domain.Role;
import com.conecta.authorization_api.authorization_api.repository.IdentityRepository;
import com.conecta.authorization_api.authorization_api.repository.InvitationRepository;
import com.conecta.authorization_api.authorization_api.repository.RoleRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class InfrastructureOperationsService {
    private final IdentityRepository identities;
    private final RoleRepository roles;
    private final InvitationRepository invitations;
    private final JdbcTemplate jdbc;
    private final AccountNotificationService notifications;
    private final AuditService audit;
    private final AccessRevocationService revocation;
    private final SessionRegistry browserSessions;
    private final PasswordEncoder passwordEncoder;

    public InfrastructureOperationsService(IdentityRepository identities, RoleRepository roles, InvitationRepository invitations,
                                           JdbcTemplate jdbc, AccountNotificationService notifications, AuditService audit,
                                           AccessRevocationService revocation, SessionRegistry browserSessions, PasswordEncoder passwordEncoder) {
        this.identities = identities;
        this.roles = roles;
        this.invitations = invitations;
        this.jdbc = jdbc;
        this.notifications = notifications;
        this.audit = audit;
        this.revocation = revocation;
        this.browserSessions = browserSessions;
        this.passwordEncoder = passwordEncoder;
    }

    public List<IdentityView> identities() {
        return identities.findAll().stream().map(this::view).toList();
    }

    public List<String> roles() {
        return roles.findAll().stream().map(Role::getName).sorted().toList();
    }

    public List<RoleView> roleViews() {
        return jdbc.query("SELECT r.id, r.name, r.is_system, count(ir.identity_id) FROM auth.role r LEFT JOIN auth.identity_role ir ON ir.role_id = r.id GROUP BY r.id, r.name, r.is_system ORDER BY r.name", (row, index) -> new RoleView(UUID.fromString(row.getString(1)), row.getString(2), row.getBoolean(3), row.getLong(4)));
    }

    @Transactional
    public RoleView createRole(String name) {
        if (roles.findByName(name).isPresent()) throw new IllegalArgumentException("Role already exists");
        Role role = roles.save(Role.custom(name));
        audit.record("ROLE_CREATED", "ROLE", name);
        return new RoleView(role.getId(), role.getName(), false, 0);
    }

    @Transactional
    public void renameRole(UUID id, String name) {
        Role role = roles.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown role"));
        if (roles.findByName(name).filter(existing -> !existing.getId().equals(id)).isPresent()) {
            throw new IllegalStateException("Role name already exists");
        }
        identities.findAll().stream().filter(identity -> identity.getRoles().contains(role))
                .forEach(identity -> revocation.revokeUser(identity.getUsername()));
        role.rename(name);
        audit.record("ROLE_RENAMED", "ROLE", id.toString());
    }

    @Transactional
    public void deleteRole(UUID id) {
        Role role = roles.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown role"));
        if (role.isSystem()) throw new IllegalStateException("System roles cannot be deleted");
        Integer members = jdbc.queryForObject("SELECT count(*) FROM auth.identity_role WHERE role_id = ?", Integer.class, id);
        if (members != null && members > 0)
            throw new IllegalStateException("Reassign members before deleting this role");
        roles.delete(role);
        audit.record("ROLE_DELETED", "ROLE", id.toString());
    }

    @Transactional
    public void replaceRoles(UUID id, Set<String> names) {
        Identity identity = identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity"));
        if (!names.contains("INFRASTRUCTURE_INTERNAL")) protectLastOperator(identity);
        Set<Role> assigned = new HashSet<>();
        for (String name : names)
            assigned.add(roles.findByName(name).orElseThrow(() -> new IllegalArgumentException("Unknown role: " + name)));
        identity.replaceRoles(assigned);
        revocation.revokeUser(identity.getUsername());
        audit.record("IDENTITY_ROLES_CHANGED", "IDENTITY", id.toString());
    }

    @Transactional
    public void block(UUID id, boolean blocked) {
        Identity identity = identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity"));
        if (blocked) protectLastOperator(identity);
        if (blocked) identity.block();
        else identity.unblock();
        if (blocked) revocation.revokeUser(identity.getUsername());
        audit.record(blocked ? "IDENTITY_BLOCKED" : "IDENTITY_UNBLOCKED", "IDENTITY", id.toString());
    }

    @Transactional
    public void updateIdentity(UUID id, String username, String email, boolean active) {
        Identity identity = identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity"));
        if (!identity.getUsername().equals(username)) throw new IllegalArgumentException("Username is immutable");
        if (!active) protectLastOperator(identity);
        identities.findByUsername(username).filter(other -> !other.getId().equals(id)).ifPresent(other -> {
            throw new IllegalArgumentException("Username already exists");
        });
        identities.findByEmailIgnoreCase(email).filter(other -> !other.getId().equals(id)).ifPresent(other -> {
            throw new IllegalArgumentException("Email already exists");
        });
        identity.updateProfile(username, email.toLowerCase());
        identity.setActive(active);
        revocation.revokeUser(identity.getUsername());
        audit.record("IDENTITY_UPDATED", "IDENTITY", id.toString());
    }

    @Transactional
    public void updateIdentityAndRoles(UUID id, String username, String email, boolean active, Set<String> names) {
        if (!names.contains("INFRASTRUCTURE_INTERNAL")) {
            protectLastOperator(identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity")));
        }
        updateIdentity(id, username, email, active);
        replaceRoles(id, names);
    }

    @Transactional
    public void deleteIdentity(UUID id) {
        Identity identity = identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity"));
        protectLastOperator(identity);
        revocation.revokeUser(identity.getUsername());
        jdbc.update("DELETE FROM auth.oauth2_authorization_consent WHERE principal_name = ?", identity.getUsername());
        identities.delete(identity);
        audit.record("IDENTITY_DELETED", "IDENTITY", id.toString());
    }

    @Transactional
    public void invite(String email, Set<String> names) {
        if (identities.findByEmailIgnoreCase(email).isPresent()) throw new IllegalStateException("An identity with this email already exists");
        for (String n : names)
            if (roles.findByName(n).isEmpty()) throw new IllegalArgumentException("Unknown role: " + n);
        String raw = UUID.randomUUID().toString();
        Invitation invite = invitations.save(Invitation.issue(email, String.join(",", names), hash(raw), SecurityContextHolder.getContext().getAuthentication().getName()));
        notifications.sendInvitation(email, raw);
        audit.record("INVITATION_CREATED", "INVITATION", invite.getEmail());
    }

    @Transactional
    public void revokeInvitation(UUID id) {
        Invitation invitation = invitations.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown invitation"));
        invitation.revoke();
        audit.record("INVITATION_REVOKED", "INVITATION", id.toString());
    }

    @Transactional
    public void resendInvitation(UUID id) {
        Invitation invitation = invitations.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown invitation"));
        if (invitation.isAccepted()) throw new IllegalStateException("Invitation already accepted");
        invitation.revoke();
        invite(invitation.getEmail(), new HashSet<>(Arrays.asList(invitation.getRoleNames().split(","))));
        audit.record("INVITATION_RESENT", "INVITATION", id.toString());
    }

    @Transactional
    public IdentityView createIdentity(String username, String email, String password, Set<String> names) {
        if (identities.findByUsername(username).isPresent() || identities.findByEmailIgnoreCase(email).isPresent()) {
            throw new IllegalStateException("Identity already exists");
        }
        Set<Role> assigned = names.stream().map(name -> roles.findByName(name)
                .orElseThrow(() -> new IllegalArgumentException("Unknown role: " + name))).collect(java.util.stream.Collectors.toSet());
        Identity identity = Identity.pendingRegistration(username, email.toLowerCase(Locale.ROOT), passwordEncoder.encode(password), assigned);
        identity.activate();
        identities.save(identity);
        audit.record("IDENTITY_CREATED", "IDENTITY", identity.getId().toString());
        return view(identity);
    }

    @Transactional
    public void revokeIdentityAccess(UUID id) {
        Identity identity = identities.findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown identity"));
        revocation.revokeUser(identity.getUsername());
        audit.record("IDENTITY_ACCESS_REVOKED", "IDENTITY", id.toString());
    }

    public List<BrowserSessionView> browserSessions() {
        return browserSessions.getAllPrincipals().stream().filter(UserDetails.class::isInstance)
                .flatMap(principal -> browserSessions.getAllSessions(principal, false).stream()
                        .map(session -> new BrowserSessionView(hash(session.getSessionId()), ((UserDetails) principal).getUsername(), session.getLastRequest().toInstant().toString())))
                .toList();
    }

    public void revokeBrowserSession(String handle) {
        browserSessions.getAllPrincipals().forEach(principal -> browserSessions.getAllSessions(principal, false).stream()
                .filter(session -> hash(session.getSessionId()).equals(handle)).forEach(session -> session.expireNow()));
        audit.record("BROWSER_SESSION_REVOKED", "BROWSER_SESSION", handle);
    }

    private void protectLastOperator(Identity identity) {
        if (identity.getRoles().stream().noneMatch(role -> role.getName().equals("INFRASTRUCTURE_INTERNAL"))) return;
        jdbc.queryForObject("SELECT id FROM auth.role WHERE name = 'INFRASTRUCTURE_INTERNAL' FOR UPDATE", UUID.class);
        Long operators = jdbc.queryForObject("""
                SELECT count(*) FROM auth.identity i JOIN auth.identity_role ir ON i.id = ir.identity_id
                JOIN auth.role r ON r.id = ir.role_id
                WHERE r.name = 'INFRASTRUCTURE_INTERNAL' AND i.is_active AND NOT i.is_blocked
                """, Long.class);
        if (identity.isActive() && !identity.isBlocked() && operators != null && operators <= 1) {
            throw new IllegalStateException("Cannot remove the last active infrastructure operator");
        }
    }

    public List<Map<String, Object>> invitations() {
        return jdbc.queryForList("SELECT id,email,role_names,expires_at,accepted_at,revoked_at,created_at FROM auth.invitation ORDER BY created_at DESC");
    }

    public List<Map<String, Object>> sessions() {
        return jdbc.queryForList("SELECT id,principal_name,authorization_grant_type,access_token_issued_at,access_token_expires_at,refresh_token_expires_at FROM auth.oauth2_authorization ORDER BY access_token_issued_at DESC NULLS LAST");
    }

    @Transactional
    public void revokeSession(String id) {
        jdbc.update("DELETE FROM auth.oauth2_authorization WHERE id = ?", id);
        audit.record("AUTHORIZATION_REVOKED", "AUTHORIZATION", id);
    }

    public List<Map<String, Object>> auditEvents() {
        return jdbc.queryForList("SELECT actor_username,action,target_type,target_id,created_at FROM auth.audit_event ORDER BY created_at DESC LIMIT 500");
    }

    public List<Map<String, Object>> accessEvents() {
        return jdbc.queryForList("SELECT username,event_type,remote_address,user_agent,created_at FROM auth.access_event ORDER BY created_at DESC LIMIT 500");
    }

    private IdentityView view(Identity i) {
        return new IdentityView(i.getId(), i.getUsername(), i.getEmail(), i.isActive(), i.isBlocked(), i.getRoles().stream().map(Role::getName).sorted().toList());
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record IdentityView(UUID id, String username, String email, boolean active, boolean blocked,
                               List<String> roles) {
    }

    public record RoleView(UUID id, String name, boolean system, long memberCount) {
    }
    public record BrowserSessionView(String id, String username, String lastRequest) { }
}
