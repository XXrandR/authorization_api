package com.conecta.authorization_api.authorization_api.repository;

import com.conecta.authorization_api.authorization_api.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByName(String name);
}
