package com.example.authserver.rbac;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="api_to_roles")
@Getter @Setter
public class ApiRoleEntity {
    @Id @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="role_id")
    private RoleEntity role;

    private String action;
}
