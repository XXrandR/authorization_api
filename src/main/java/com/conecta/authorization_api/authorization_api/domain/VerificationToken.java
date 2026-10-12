package com.conecta.authorization_api.authorization_api.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "verification_token", schema = "auth")
public class VerificationToken {

    @Id
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "identity_id", nullable = false)
    private Identity identity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private VerificationTokenType type;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "consumed_at")
    private OffsetDateTime consumedAt;

    protected VerificationToken() {
    }

    public static VerificationToken issue(
            Identity identity,
            VerificationTokenType type,
            String tokenHash,
            OffsetDateTime expiresAt) {
        VerificationToken token = new VerificationToken();
        token.id = UUID.randomUUID();
        token.identity = identity;
        token.type = type;
        token.tokenHash = tokenHash;
        token.expiresAt = expiresAt;
        return token;
    }

    public boolean isUsableAt(OffsetDateTime now) {
        return consumedAt == null && expiresAt.isAfter(now);
    }

    public Identity getIdentity() {
        return identity;
    }

    public void consume(OffsetDateTime now) {
        consumedAt = now;
    }
}
