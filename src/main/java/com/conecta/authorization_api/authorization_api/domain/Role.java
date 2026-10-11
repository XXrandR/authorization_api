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
}
