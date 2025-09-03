package com.example.authserver.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="client_scopes")
@Getter @Setter
public class ClientScopeEntity {
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private ClientEntity client;
    
    @Column(nullable = false)
    private String scope;
    
    public ClientScopeEntity() {}
    
    public ClientScopeEntity(ClientEntity client, String scope) {
        this.client = client;
        this.scope = scope;
    }
}