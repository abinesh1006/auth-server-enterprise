package com.example.authserver.mfa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserMfaRepository extends JpaRepository<UserMfaEntity, UUID> {
    Optional<UserMfaEntity> findByUserId(UUID userId);
}
