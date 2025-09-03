package com.example.authserver.rbac;

import com.example.authserver.user.UserEntity;
import com.example.authserver.tenant.TenantEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRoleEntity, UUID> {
    List<UserRoleEntity> findByUserAndTenant(UserEntity user, TenantEntity tenant);
    
    @Query("SELECT ur FROM UserRoleEntity ur JOIN FETCH ur.role WHERE ur.user = ?1 AND ur.tenant = ?2")
    List<UserRoleEntity> findByUserAndTenantWithRole(UserEntity user, TenantEntity tenant);
}