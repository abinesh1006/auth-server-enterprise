package com.example.authserver.rbac;

import com.example.authserver.tenant.TenantEntity;
import com.example.authserver.user.UserEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="users_to_roles")
@Getter @Setter
public class UserRoleEntity {
    @Id @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="tenant_id")
    private TenantEntity tenant;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="role_id")
    private RoleEntity role;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="user_id")
    private UserEntity user;
}
