package com.example.authserver.tenant;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity @Table(name = "tenants")
@Getter @Setter
public class TenantEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="tenant_key", unique = true, nullable = false)
    private String tenantKey;

    @Column(unique = true, nullable = false)
    private String domain;

    private String owner;
}