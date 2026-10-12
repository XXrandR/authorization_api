package com.conecta.authorization_api.authorization_api.service;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import com.conecta.authorization_api.authorization_api.domain.Invitation;
import com.conecta.authorization_api.authorization_api.domain.Role;
import com.conecta.authorization_api.authorization_api.domain.VerificationToken;
import com.conecta.authorization_api.authorization_api.domain.VerificationTokenType;
import com.conecta.authorization_api.authorization_api.repository.IdentityRepository;
import com.conecta.authorization_api.authorization_api.repository.InvitationRepository;
import com.conecta.authorization_api.authorization_api.repository.RoleRepository;
import com.conecta.authorization_api.authorization_api.repository.VerificationTokenRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;

@Service
public class AccountService {
    private final IdentityRepository identities;
    private final RoleRepository roles;
    private final VerificationTokenRepository tokens;
    private final InvitationRepository invitations;
    private final PasswordEncoder passwordEncoder;
    private final AccountNotificationService notifications;
    private final AccessRevocationService revocation;
    private final AuditService audit;

    public AccountService(IdentityRepository identities, RoleRepository roles,
                          VerificationTokenRepository tokens, InvitationRepository invitations, PasswordEncoder passwordEncoder,
                          AccountNotificationService notifications, AccessRevocationService revocation, AuditService audit) {
        this.identities = identities;
        this.roles = roles;
        this.tokens = tokens;
        this.invitations = invitations;
        this.passwordEncoder = passwordEncoder;
        this.notifications = notifications;
        this.revocation = revocation;
        this.audit = audit;
    }

    @Transactional
    public void register(String username, String email, String password, String invitationToken) {
        if (identities.findByUsername(username).isPresent() || identities.findByEmailIgnoreCase(email).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "An account with those details already exists");
        }
        Set<Role> assignedRoles = invitationToken == null || invitationToken.isBlank()
                ? Set.of(requiredRole("USER")) : consumeInvitation(invitationToken, email);
        Identity identity = identities.save(Identity.pendingRegistration(
                username, email.toLowerCase(), passwordEncoder.encode(password), assignedRoles));
        notifications.sendEmailVerification(email, issue(identity, VerificationTokenType.EMAIL_VERIFICATION, 24));
        audit.record("ACCOUNT_REGISTERED", "IDENTITY", identity.getId().toString());
    }

    private Role requiredRole(String name) { return roles.findByName(name).orElseThrow(() -> new IllegalStateException("Required role is not configured: " + name)); }

    private Set<Role> consumeInvitation(String rawToken, String email) {
        Invitation invitation = invitations.findByTokenHash(hash(rawToken)).filter(item -> item.isUsable(email))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "The invitation is invalid or expired"));
        Set<Role> assigned = java.util.Arrays.stream(invitation.getRoleNames().split(",")).map(this::requiredRole).collect(java.util.stream.Collectors.toSet());
        invitation.accept();
        return assigned;
    }

    @Transactional
    public void verifyEmail(String rawToken) {
        VerificationToken token = usableToken(rawToken, VerificationTokenType.EMAIL_VERIFICATION);
        token.getIdentity().activate();
        token.consume(OffsetDateTime.now());
        audit.record("EMAIL_VERIFIED", "IDENTITY", token.getIdentity().getId().toString());
    }

    @Transactional
    public void requestPasswordReset(String email) {
        identities.findByEmailIgnoreCase(email).ifPresent(identity ->
                notifications.sendPasswordReset(identity.getEmail(), issue(identity, VerificationTokenType.PASSWORD_RESET, 1)));
    }

    @Transactional
    public void resetPassword(String rawToken, String password) {
        VerificationToken token = usableToken(rawToken, VerificationTokenType.PASSWORD_RESET);
        token.getIdentity().changePassword(passwordEncoder.encode(password));
        token.consume(OffsetDateTime.now());
        tokens.invalidate(token.getIdentity().getId(), VerificationTokenType.PASSWORD_RESET);
        revocation.revokeUser(token.getIdentity().getUsername());
        audit.record("PASSWORD_RESET", "IDENTITY", token.getIdentity().getId().toString());
    }

    @Transactional
    public void resendVerification(String email) {
        identities.findByEmailIgnoreCase(email).filter(identity -> !identity.isEmailVerified()).ifPresent(identity ->
                notifications.sendEmailVerification(identity.getEmail(), issue(identity, VerificationTokenType.EMAIL_VERIFICATION, 24)));
    }

    private String issue(Identity identity, VerificationTokenType type, long validHours) {
        tokens.invalidate(identity.getId(), type);
        String rawToken = UUID.randomUUID().toString();
        tokens.save(VerificationToken.issue(identity, type, hash(rawToken), OffsetDateTime.now().plusHours(validHours)));
        return rawToken;
    }

    private VerificationToken usableToken(String rawToken, VerificationTokenType type) {
        return tokens.findByTokenHashAndType(hash(rawToken), type)
                .filter(token -> token.isUsableAt(OffsetDateTime.now()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "The link is invalid or expired"));
    }

    private static String hash(String rawToken) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to hash account token", exception);
        }
    }
}
