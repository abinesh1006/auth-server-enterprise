package com.example.authserver.rbac;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ApiRoleRepository extends JpaRepository<ApiRoleEntity, UUID> {
    List<ApiRoleEntity> findByRole_RoleIn(Iterable<String> roles);
}
