package com.example.authserver.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity @Table(name="clients")
@Getter @Setter
public class ClientEntity {
    @Id
    private UUID id;

    @Column(name="client_id", unique = true, nullable = false)
    private String clientId;

    private String clientSecret;

    private Boolean requirePkce = Boolean.FALSE;

    private Boolean requireAuthorizationConsent = Boolean.TRUE;

    // Token settings as proper columns
    private Integer accessTokenTimeToLiveMinutes = 15;

    private Integer refreshTokenTimeToLiveDays = 30;

    private Boolean reuseRefreshTokens = Boolean.TRUE;

    private Instant createdAt = Instant.now();

    // Proper one-to-many relationships - changed to LAZY fetch
    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<ClientAuthMethodEntity> authMethods = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<ClientGrantTypeEntity> grantTypes = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<ClientRedirectUriEntity> redirectUris = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<ClientScopeEntity> scopes = new HashSet<>();
}