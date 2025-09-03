package com.example.authserver.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name="client_redirect_uris")
@Getter @Setter
public class ClientRedirectUriEntity {
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private ClientEntity client;
    
    @Column(nullable = false, length = 512)
    private String redirectUri;
    
    public ClientRedirectUriEntity() {}
    
    public ClientRedirectUriEntity(ClientEntity client, String redirectUri) {
        this.client = client;
        this.redirectUri = redirectUri;
    }
}