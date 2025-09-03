package com.example.authserver.keys;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface JwkRepository extends JpaRepository<JwkEntity, UUID> {
    List<JwkEntity> findByActiveTrue();
    Optional<JwkEntity> findByKid(String kid);
}
