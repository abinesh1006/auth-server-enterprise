package com.example.authserver.tenant;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TenantRepository extends JpaRepository<TenantEntity, Long> {
    Optional<TenantEntity> findByDomain(String domain);
    Optional<TenantEntity> findByTenantKey(String key);
}
