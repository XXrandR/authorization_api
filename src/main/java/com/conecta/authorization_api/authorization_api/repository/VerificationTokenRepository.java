package com.conecta.authorization_api.authorization_api.repository;

import com.conecta.authorization_api.authorization_api.domain.VerificationToken;
import com.conecta.authorization_api.authorization_api.domain.VerificationTokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    Optional<VerificationToken> findByTokenHashAndType(String tokenHash, VerificationTokenType type);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("update VerificationToken t set t.consumedAt = CURRENT_TIMESTAMP where t.identity.id = :id and t.type = :type and t.consumedAt is null")
    void invalidate(java.util.UUID id, VerificationTokenType type);
}
