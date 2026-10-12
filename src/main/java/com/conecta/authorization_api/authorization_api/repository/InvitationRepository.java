package com.conecta.authorization_api.authorization_api.repository;

import com.conecta.authorization_api.authorization_api.domain.Invitation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface InvitationRepository extends JpaRepository<Invitation, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    Optional<Invitation> findByTokenHash(String tokenHash);
}
