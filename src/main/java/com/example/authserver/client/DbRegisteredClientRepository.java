package com.example.authserver.client;

import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class DbRegisteredClientRepository implements RegisteredClientRepository {

    public final ClientRepository repository;

    public DbRegisteredClientRepository(ClientRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional
    @CacheEvict(value = "clients", key = "#registeredClient.clientId")
    public void save(RegisteredClient registeredClient) {
        // Find existing or create new
        ClientEntity entity = repository.findByClientId(registeredClient.getClientId())
                .orElse(new ClientEntity());
        
        // Update all fields
        if (entity.getId() == null) {
            entity.setId(UUID.randomUUID());
            entity.setCreatedAt(java.time.Instant.now());
        }
        entity.setClientId(registeredClient.getClientId());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setRequirePkce(registeredClient.getClientSettings().isRequireProofKey());
        entity.setRequireAuthorizationConsent(registeredClient.getClientSettings().isRequireAuthorizationConsent());
        
        // Set token settings from proper fields
        var tokenSettings = registeredClient.getTokenSettings();
        entity.setAccessTokenTimeToLiveMinutes((int) tokenSettings.getAccessTokenTimeToLive().toMinutes());
        entity.setRefreshTokenTimeToLiveDays((int) tokenSettings.getRefreshTokenTimeToLive().toDays());
        entity.setReuseRefreshTokens(tokenSettings.isReuseRefreshTokens());
        
        // Clear existing relationships
        entity.getAuthMethods().clear();
        entity.getGrantTypes().clear();
        entity.getRedirectUris().clear();
        entity.getScopes().clear();
        
        // Add new relationships
        registeredClient.getClientAuthenticationMethods().forEach(method -> 
            entity.getAuthMethods().add(new ClientAuthMethodEntity(entity, method.getValue())));
        
        registeredClient.getAuthorizationGrantTypes().forEach(grantType -> 
            entity.getGrantTypes().add(new ClientGrantTypeEntity(entity, grantType.getValue())));
        
        registeredClient.getRedirectUris().forEach(uri -> 
            entity.getRedirectUris().add(new ClientRedirectUriEntity(entity, uri)));
        
        registeredClient.getScopes().forEach(scope -> 
            entity.getScopes().add(new ClientScopeEntity(entity, scope)));
        
        repository.save(entity);
    }

    @Override
    @Cacheable(value = "clients", key = "#id")
    public RegisteredClient findById(String id) {
        return repository.findByIdWithRelationships(UUID.fromString(id)).map(this::toRegisteredClient).orElse(null);
    }

    @Override
    @Cacheable(value = "clients", key = "#clientId")
    public RegisteredClient findByClientId(String clientId) {
        return repository.findByClientIdWithRelationships(clientId).map(this::toRegisteredClient).orElse(null);
    }

    private RegisteredClient toRegisteredClient(ClientEntity e) {
        var tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(java.time.Duration.ofMinutes(e.getAccessTokenTimeToLiveMinutes()))
                .refreshTokenTimeToLive(java.time.Duration.ofDays(e.getRefreshTokenTimeToLiveDays()))
                .reuseRefreshTokens(e.getReuseRefreshTokens())
                .build();
                
        var clientSettings = ClientSettings.builder()
                .requireProofKey(Boolean.TRUE.equals(e.getRequirePkce()))
                .requireAuthorizationConsent(Boolean.TRUE.equals(e.getRequireAuthorizationConsent()))
                .build();

        RegisteredClient.Builder b = RegisteredClient.withId(e.getId().toString())
                .clientId(e.getClientId())
                .clientSecret(e.getClientSecret())
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings);

        e.getAuthMethods().forEach(am -> b.clientAuthenticationMethod(new ClientAuthenticationMethod(am.getAuthMethod())));
        e.getGrantTypes().forEach(gt -> b.authorizationGrantType(new AuthorizationGrantType(gt.getGrantType())));
        e.getRedirectUris().forEach(ru -> b.redirectUri(ru.getRedirectUri()));
        e.getScopes().forEach(s -> b.scope(s.getScope()));

        return b.build();
    }
    
    // Add cache eviction for bulk operations if you have them
    @CacheEvict(value = "clients", allEntries = true)
    public void evictAllClients() {
        // Method to clear entire cache when needed
    }
}