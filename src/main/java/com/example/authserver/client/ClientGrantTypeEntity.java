package com.example.authserver.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="client_grant_types")
@Getter @Setter
public class ClientGrantTypeEntity {
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private ClientEntity client;
    
    @Column(nullable = false)
    private String grantType;
    
    public ClientGrantTypeEntity() {}
    
    public ClientGrantTypeEntity(ClientEntity client, String grantType) {
        this.client = client;
        this.grantType = grantType;
    }
}