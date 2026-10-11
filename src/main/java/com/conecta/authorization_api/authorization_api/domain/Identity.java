package com.conecta.authorization_api.authorization_api.domain;

import jakarta.persistence.Table;
import lombok.Getter;

import java.time.OffsetDateTime;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.*;

@Getter
@Entity
@Table(name = "identity", schema = "auth")
public class Identity {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    private String phone;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "email_verified")
    private boolean emailVerified;

    @Column(name = "phone_verified")
    private boolean phoneVerified;

    @Column(name = "is_active")
    private boolean active = true;

    @Column(name = "is_blocked")
    private boolean blocked = false;

    @Column(name = "person_id", nullable = false)
    private UUID personId;

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at")
    private OffsetDateTime updatedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "identity_role",
            schema = "auth",
            joinColumns = @JoinColumn(name = "identity_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles;

    @PrePersist
    void prePersist() {
        createdAt = OffsetDateTime.now();
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
