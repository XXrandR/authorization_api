package com.conecta.authorization_api.authorization_api.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;

import java.util.UUID;

@Getter
@Entity
@Table(name = "role", schema = "auth")
public class Role {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(name = "is_system", nullable = false)
    private boolean system;

    public static Role custom(String name) {
        Role role = new Role();
        role.id = UUID.randomUUID();
        role.name = name;
        return role;
    }

    public void rename(String name) {
        if (system) throw new IllegalStateException("System roles cannot be renamed");
        this.name = name;
    }
}
