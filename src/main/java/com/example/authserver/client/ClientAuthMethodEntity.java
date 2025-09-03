package com.example.authserver.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="client_auth_methods")
@Getter @Setter
public class ClientAuthMethodEntity {
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private ClientEntity client;
    
    @Column(nullable = false)
    private String authMethod;
    
    public ClientAuthMethodEntity() {}
    
    public ClientAuthMethodEntity(ClientEntity client, String authMethod) {
        this.client = client;
        this.authMethod = authMethod;
    }
}