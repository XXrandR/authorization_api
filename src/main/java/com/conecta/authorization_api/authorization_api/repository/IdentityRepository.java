package com.conecta.authorization_api.authorization_api.repository;

import com.conecta.authorization_api.authorization_api.domain.Identity;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface IdentityRepository extends JpaRepository<Identity,UUID> {
    Optional<Identity> findByUsername(@NonNull String username);
    Optional<Identity> findByEmailIgnoreCase(String email);
    Optional<Identity> findByUsernameAndRolesName(String username, String roleName);
}
