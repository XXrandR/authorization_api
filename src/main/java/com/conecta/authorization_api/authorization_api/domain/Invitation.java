package com.conecta.authorization_api.authorization_api.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "invitation", schema = "auth")
public class Invitation {
    @Id private UUID id;
    @Column(nullable = false) private String email;
    @Column(name = "role_names", nullable = false) private String roleNames;
    @Column(name = "token_hash", nullable = false, unique = true) private String tokenHash;
    @Column(name = "expires_at", nullable = false) private OffsetDateTime expiresAt;
    @Column(name = "accepted_at") private OffsetDateTime acceptedAt;
    @Column(name = "revoked_at") private OffsetDateTime revokedAt;
    @Column(name = "created_by", nullable = false) private String createdBy;
    protected Invitation() {}
    public static Invitation issue(String email, String roleNames, String tokenHash, String createdBy) {
        Invitation invitation = new Invitation(); invitation.id = UUID.randomUUID(); invitation.email = email.toLowerCase(); invitation.roleNames = roleNames; invitation.tokenHash = tokenHash; invitation.createdBy = createdBy; invitation.expiresAt = OffsetDateTime.now().plusDays(7); return invitation;
    }
    public boolean isUsable(String email) { return acceptedAt == null && revokedAt == null && expiresAt.isAfter(OffsetDateTime.now()) && this.email.equalsIgnoreCase(email); }
    public void accept() { acceptedAt = OffsetDateTime.now(); }
    public void revoke() { revokedAt = OffsetDateTime.now(); }
    public String getEmail() { return email; }
    public String getRoleNames() { return roleNames; }
    public String getTokenHash() { return tokenHash; }
    public boolean isAccepted() { return acceptedAt != null; }
}
